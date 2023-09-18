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
                  [(walk ?from ?attr ?to)
                   [?from ?attr ?to]]
                  [(walk ?from ?attr ?to)
                   [?from ?attr ?intermediate]
                   (walk ?intermediate ?attr ?to)]

                  [(p-equivalent ?e ?p)
                   [(identity ?e) ?p]]
                  [(p-equivalent ?e ?p)
                   (walk ?e :liminal.principal/children ?p)]
                  [(p-equivalent ?e ?p)
                   [?p :db/ident :liminal.principal/*]]

                  [(r-equivalent ?e ?r)
                   [(identity ?e) ?r]]
                  [(r-equivalent ?e ?r)
                   (walk ?e :liminal.resource/children ?r)]
                  [(r-equivalent ?e ?r)
                   [?r :db/ident :liminal.resource/*]]

                  [(a-equivalent ?e ?a)
                   [(identity ?e) ?a]]
                  [(a-equivalent ?e ?a)
                   [(ground :liminal.action/*) ?a]]

                  ;; This rule unifies the candidate principle (?p), action (?a) and resource (?r) to a policy.
                  [(policy ?policy ?p ?a ?r)
                   [?policy :liminal.policy/principal ?p]
                   [?policy :liminal.policy/action ?a]
                   [?policy :liminal.policy/resource ?r]]

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

(defn list-scopes
  [db principal action resource]
  (d/q {:query {:find '[?p ?a ?r]
                :in '[$ % ?principal ?action ?resource]
                :where '[(p-equivalent ?principal ?p)
                         (a-equivalent ?action ?a)
                         (r-equivalent ?resource ?r)]}
        :args [db base-rules principal action resource]}))

(defn evaluate
  [db principals action resource {:keys [context rules] :or {context {} rules []} :as options}]
  (let [rules (concat base-rules rules)
        policies (->> (d/q {:query '[:find (pull ?policy [*])
                                     :in $ % [?principal ...] ?action ?resource
                                     :where
                                     , (p-equivalent ?principal ?p)
                                     , (a-equivalent ?action ?a)
                                     , (r-equivalent ?resource ?r)
                                     , (policy ?policy ?p ?a ?r)]
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
