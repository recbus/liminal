(ns io.recbus.liminal
  (:require [datomic.client.api :as d]))

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

                  ;; This rule unifies the candidate principle (?p), action (?a) and resource (?r) to a policy ?policy,
                  ;; where principal and resource unification can either be through explicit entity attributes or indirectly
                  ;; via a schema attribute entity.
                  [(policy ?policy ?p ?a ?r)
                   (or-join [?policy ?p]
                            [?policy :liminal.policy/principal ?p]
                            (and [?policy :liminal.policy/principal ?attr]
                                 [?p ?attr]))
                   [?policy :liminal.policy/action ?a]
                   (or-join [?policy ?r]
                            [?policy :liminal.policy/resource ?r]
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

(def reverse-walk-rules '[[(*p ?p ?e)
                           [(identity ?p) ?e]]
                          [(*p ?p ?e)
                           (p-walk ?e ?p)]

                          [(*r ?r ?e)
                           [(identity ?r) ?e]]
                          [(*r ?r ?e)
                           (r-walk ?e ?r)]

                          [(*a ?a ?e)
                           [(identity ?a) ?e]]])

(defn- policy-comparator
  "Compare by effectivity (higher first) then deny-before-permit."
  [{e0 :liminal.policy/effectivity p0? :liminal.policy/permit?}
   {e1 :liminal.policy/effectivity p1? :liminal.policy/permit?}]
  (compare [e1 (not p1?)] [e0 (not p0?)]))

(defn policies
  "Find applicable policies (and satisfying values) for arbitrary combinations of
  the three constraints #{`principal`, `action`, `resource`}."
  [db principal action resource {:keys [context rules] :or {context {} rules []} :as options}]
  (let [rules (concat base-rules reverse-walk-rules rules)
        inputs [[principal '[?principal ?p ?p-out p* *p (pull ?p-out [:db/ident])]]
                [action '[?action ?a ?a-out a* *a ?a-out]]
                [resource '[?resource ?r ?r-out r* *r (pull ?r-out [:db/ident])]]]
        q {:query '{:find [(pull ?policy [*])]
                    :in [$ % [?principal ?action ?resource]]
                    :where [(policy ?policy ?p ?a ?r)]}
           :args [db rules [principal action resource]]}
        q (reduce (fn [q [v [input b-name output clause* *clause find]]]
                    (if (nil? v)
                      (-> q
                          (update-in [:query :find] conj find)
                          (update-in [:query :where] conj (list *clause b-name output)))
                      (-> q
                          (update-in [:query :where] (comp vec #(concat [(list clause* input b-name)] %))))))
                  q
                  inputs)]
    (->> (d/q q)
         (sort-by first policy-comparator))))

(defn- satisfied?
  [context {condition :liminal.policy/condition :as policy}]
  (if condition
    (if-let [f (requiring-resolve condition)]
      (when (f context) policy)
      (throw (ex-info "Condition symbol not resolved!" {::condition condition ::context context})))
    policy))

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
                      (sort policy-comparator))
        ;; Evaluate policies such that the presumably expensive `satisfied?` operation is short-circuted as soon as possible
        decision (:liminal.policy/permit? (some (partial satisfied? context) policies))]
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
