(ns io.recbus.liminal
  (:require [datomic.client.api :as d]))

(defn- drop-when-change
  "Return a stateful transducer that drops all remaining elements when (f element) changes from (f (first element))."
  [f]
  (fn [rf]
    (let [tracker (volatile! ::none)]
      (fn drop-when-change
        ([] (rf))
        ([coll] (rf coll))
        ([coll element]
         (let [v (f element)]
           (if (identical? @tracker ::none)
             (do (vreset! tracker v)
                 (rf coll element))
             (if (= @tracker v)
               (rf coll element)
               (ensure-reduced coll)))))))))

(defn- satisfied?
  [condition context]
  (if-let [f (requiring-resolve condition)]
    (f context)
    (throw (ex-info "Condition symbol not resolved!" {::condition condition ::context context}))))

(def base-rules '[;; walk a graph from ?from to ?to via ?attr
                  [(p-walk ?from ?to)
                   [?from :liminal.principal/children ?to]]
                  [(p-walk ?from ?to)
                   [?from :liminal.principal/children ?intermediate]
                   (p-walk ?intermediate ?to)]

                  [(r-walk ?from ?to)
                   [?from :liminal.resource/children ?to]]
                  [(r-walk ?from ?to)
                   [?from :liminal.resource/children ?intermediate]
                   (r-walk ?intermediate ?to)]

                  [(p* ?e ?p)
                   [(identity ?e) ?p]]
                  [(p* ?e ?p)
                   (p-walk ?e ?p)]
                  [(p* ?e ?p)
                   [?p :db/ident :liminal.principal/*]]

                  [(r* ?e ?r)
                   [(identity ?e) ?r]]
                  [(r* ?e ?r)
                   (r-walk ?r ?e)]
                  [(r* ?e ?r)
                   [?r :db/ident :liminal.resource/*]]

                  [(a* ?e ?a)
                   [(identity ?e) ?a]]
                  [(a* ?e ?a)
                   [(ground :liminal.action/*) ?a]]

                  [(*p ?p ?e)
                   [(identity ?p) ?e]]
                  [(*p ?p ?e)
                   (p-walk ?e ?p)]

                  [(*r ?r ?e)
                   [(identity ?r) ?e]]
                  [(*r ?r ?e)
                   (r-walk ?e ?r)]

                  [(*a ?a ?e)
                   [(identity ?a) ?e]]

                  ;; This rule unifies the candidate principle (?p), action (?a) and resource (?r) to a policy ?policy,
                  ;; where principal and resource unification can either be through explicit entity attributes or indirectly
                  ;; via a schema attribute entity.
                  [(policy ?policy ?p ?a ?r)
                   (or-join [?policy ?p]
                            (and [?policy :liminal.policy/principal ?p]
                                 (not [?p :db/valueType]))
                            (and [?policy :liminal.policy/principal ?attr]
                                 [?p ?attr]))
                   [?policy :liminal.policy/action ?a]
                   (or-join [?policy ?r]
                            (and [?policy :liminal.policy/resource ?r]
                                 (not [?r :db/valueType]))
                            (and [?policy :liminal.policy/resource ?attr]
                                 [?r ?attr]))]

                  ;; This rule unifies the candidate ?action with the policy action while introducing the ?relation
                  ;; keyword which must unify (along with the candidate principal ?p and resource ?r) with the
                  ;; pr-relation`rule.  Idiomatically, `pr-relation` unifies the principle ?p and resource ?r
                  ;; via a reference relationship while the ?relation is bound explicitly to the keyword naming
                  ;; the relationship.
                  [(policy ?policy ?p ?a ?r)
                   [?policy :liminal.policy/action ?a]
                   [?policy :liminal.policy/relation ?relation]
                   (pr-relation ?p ?r ?relation)]

                  ;; This is the degenerate/default pr-relation rule binding the ?relation term to a sentinel value
                  ;; that should never be enumerated on any policy.
                  [(pr-relation ?p ?r ?relation)
                   [(ground ::unknown) ?relation]]])

(defn policies
  "Find applicable policies (and satisfying values) for arbitrary combinations of the three constraints #{`principal`, `action`, `resource`}."
  [db principal action resource {:keys [context rules] :or {context {} rules []} :as options}]
  (let [rules (concat base-rules rules)
        ingredients {:principal '[?principal ?p p* *p (pull ?principal [:db/ident])]
                     :action '[?action ?a a* *a ?action]
                     :resource '[?resource ?r r* *r (pull ?resource [:db/ident])]}
        inputs {:principal principal
                :action action
                :resource resource}
        q {:query '{:find [(pull ?policy [*])]
                    :in [$ %]
                    :where [(policy ?policy ?p ?a ?r)]}
           :args [db rules]}
        q (reduce (fn [q [k v]]
                    (let [[input b-name clause* *clause find] (ingredients k)]
                      (if (nil? v)
                        (-> q
                            (update-in [:query :find] conj find)
                            (update-in [:query :where] conj (list *clause b-name input)))
                        (-> q
                            (update-in [:query :in] conj input)
                            (update-in [:query :where] (comp vec #(concat [(list clause* input b-name)] %)))
                            (update :args conj v)))))
                  q
                  inputs)]
    (d/q q)))

(defn evaluate
  [db principals action resource {:keys [context rules] :or {context {} rules []} :as options}]
  (let [rules (concat base-rules rules)
        policies (->> (d/q {:query '{:find [(pull ?policy [*])]
                                     :in [$ % [?principal ...] ?action ?resource]
                                     :where [(p* ?principal ?p)
                                             (a* ?action ?a)
                                             (r* ?resource ?r)
                                             (policy ?policy ?p ?a ?r)]}
                            :args [db rules principals action resource]})
                      (map first)
                      (sort-by :liminal.policy/effectivity (fn [x y] (compare y x))))
        ;; Evaluate policies such that the presumably expensive `satisfied?` operation is short-circuted as soon as possible
        decision (when (seq policies)
                   (transduce (comp (filter (fn [{:liminal.policy/keys [condition] :as policy}]
                                              (if condition
                                                (satisfied? condition (assoc context
                                                                             ::db db
                                                                             ::policy policy
                                                                             ::principals principals
                                                                             ::action action
                                                                             ::resource resource))
                                                true)))
                                    (drop-when-change :liminal.policy/effectivity))
                              (completing (fn [allow? {:liminal.policy/keys [permit?] :as policy}]
                                            (and allow? permit?)))
                              true
                              policies))]
    [decision policies]))

(defn authorized?
  [db principals action resource & options]
  (first (evaluate db principals action resource options)))

(defn assert-authorized!
  [db principals action resource & options]
  (let [[authorized? policies] (evaluate db principals action resource options)]
    (when-not authorized?
      (throw (ex-info "Authorization denied!"
                      {::principals principals ::action action ::resource resource
                       ::options options ::policies policies})))))
