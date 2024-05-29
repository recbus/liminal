(ns io.recbus.liminal-test
  (:require [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.test :refer [are deftest is testing use-fixtures]]
            [datomic.client.api :as d]
            [datomic.local :as dl]
            [io.recbus.liminal :refer [authorized? evaluate policies] :as sut])
  (:import (java.io PushbackReader)))

(defn runt-fn!
  "`runt!` helper function"
  [f]
  (let [once-fixture-fn (clojure.test/join-fixtures (:clojure.test/once-fixtures (meta *ns*)))
        each-fixture-fn (clojure.test/join-fixtures (:clojure.test/each-fixtures (meta *ns*)))]
    (once-fixture-fn
     (fn []
       (each-fixture-fn
        (fn []
          (f)))))))

(defmacro runt!
  "Evaluate `body` with test fixtures from the current namespace."
  [& body]
  `(runt-fn! (fn [] ~@body)))

(def ^:dynamic *connection*)

(defn db-setup
  [f]
  (let [system "liminal"
        db-name "liminal"
        client (d/client {:server-type :datomic-local
                          :storage-dir :mem
                          :system system})]
    (d/create-database client {:db-name db-name})
    (binding [*connection* (d/connect client {:db-name db-name})]
      (try (f)
           (finally
             (dl/release-db {:db-name db-name :system system}) ; this appears to work on non dev-local dbs as well
             (d/delete-database client {:db-name db-name}))))))

(defn install-schema
  [f]
  (let [sources ["io/recbus/liminal/schema.edn"
                 "io/recbus/liminal/seeds.edn"]]
    (doseq [source sources]
      (let [tx-data (-> source io/resource io/reader (java.io.PushbackReader.) edn/read)]
        (d/transact *connection* {:tx-data tx-data})))
    (f)))

(defn install-fixture-data
  [f]
  (let [fsources ["fixtures/domain-attributes.edn"
                  "fixtures.edn"]]
    (doseq [fsource fsources]
      (let [tx-data (-> fsource io/resource io/reader (java.io.PushbackReader.) edn/read)]
        (d/transact *connection* {:tx-data tx-data})))
    (f)))

(use-fixtures :each db-setup install-schema install-fixture-data)

(deftest default-deny
  (let [db (d/db *connection*)]
    (is (not (authorized? db [:acme/principal0] :read :acme/resource0)))
    (is (not (authorized? db [:acme/principal0] :read :acme/resource1)))
    (is (not (authorized? db [:acme/principal1] :read :acme/resource0)))
    (is (not (authorized? db [:acme/principal1] :read :acme/resource1)))))

(deftest explicit-policy
  (let [policy {:liminal.policy/permit?   true
                :liminal.policy/effectivity 0
                :liminal.policy/principal :acme/principal0
                :liminal.policy/action    :read
                :liminal.policy/resource  :acme/resource0}
        {db :db-after} (d/transact *connection* {:tx-data [policy]})]
    (is (authorized? db [:acme/principal0] :read :acme/resource0))
    (is (not (authorized? db [:acme/principal0] :read :acme/resource1)))
    (is (not (authorized? db [:acme/principal1] :read :acme/resource0)))
    (is (not (authorized? db [:acme/principal1] :read :acme/resource1)))
    (is (not (authorized? db [:acme/principal0] :write :acme/resource0)))))

(deftest wildcard-principal-policy
  (let [policy {:liminal.policy/permit?   true
                :liminal.policy/effectivity 0
                :liminal.policy/principal :liminal.principal/*
                :liminal.policy/action    :read
                :liminal.policy/resource  :acme/resource0}
        {db :db-after} (d/transact *connection* {:tx-data [policy]})]
    (is (authorized? db [:acme/principal0] :read :acme/resource0))
    (is (not (authorized? db [:acme/principal0] :read :acme/resource1)))
    (is (authorized? db [:acme/principal1] :read :acme/resource0))
    (is (not (authorized? db [:acme/principal1] :read :acme/resource1)))))

(deftest wildcard-action-policy
  (let [policy {:liminal.policy/permit?   true
                :liminal.policy/effectivity 0
                :liminal.policy/principal :acme/principal0
                :liminal.policy/action    :liminal.action/*
                :liminal.policy/resource  :acme/resource0}
        {db :db-after} (d/transact *connection* {:tx-data [policy]})]
    (is (authorized? db [:acme/principal0] :read :acme/resource0))
    (is (not (authorized? db [:acme/principal0] :read :acme/resource1)))
    (is (not (authorized? db [:acme/principal1] :read :acme/resource0)))
    (is (not (authorized? db [:acme/principal1] :read :acme/resource1)))))

(deftest wildcard-resource-policy
  (let [policy {:liminal.policy/permit?   true
                :liminal.policy/effectivity 0
                :liminal.policy/principal :acme/principal0
                :liminal.policy/action    :read
                :liminal.policy/resource  :liminal.resource/*}
        {db :db-after} (d/transact *connection* {:tx-data [policy]})]
    (is (authorized? db [:acme/principal0] :read :acme/resource0))
    (is (authorized? db [:acme/principal0] :read :acme/resource1))
    (is (not (authorized? db [:acme/principal1] :read :acme/resource0)))
    (is (not (authorized? db [:acme/principal1] :read :acme/resource1)))))

(deftest principal-descendant-policy
  (let [policy {:liminal.policy/permit?   true
                :liminal.policy/effectivity 0
                :liminal.policy/principal :acme/principal1
                :liminal.policy/action    :read
                :liminal.policy/resource  :acme/resource0}
        relationship [:db/add :acme/principal0 :liminal.principal/children :acme/principal1]
        {db :db-after} (d/transact *connection* {:tx-data [policy relationship]})]
    (is (authorized? db [:acme/principal0] :read :acme/resource0))
    (is (not (authorized? db [:acme/principal0] :read :acme/resource1)))
    (is (authorized? db [:acme/principal1] :read :acme/resource0))
    (is (not (authorized? db [:acme/principal1] :read :acme/resource1)))))

(deftest resource-descendant-policy
  (let [policy {:liminal.policy/permit?   true
                :liminal.policy/effectivity 0
                :liminal.policy/principal :acme/principal0
                :liminal.policy/action    :read
                :liminal.policy/resource  :acme/resource0}
        relationship [:db/add :acme/resource0 :liminal.resource/children :acme/resource1]
        {db :db-after} (d/transact *connection* {:tx-data [policy relationship]})]
    (is (authorized? db [:acme/principal0] :read :acme/resource0))
    (is (authorized? db [:acme/principal0] :read :acme/resource1))
    (is (not (authorized? db [:acme/principal1] :read :acme/resource0)))
    (is (not (authorized? db [:acme/principal1] :read :acme/resource1)))))

(deftest principal-resource-relation-policy
  (let [policy {:liminal.policy/permit?   true
                :liminal.policy/effectivity 0
                :liminal.policy/action    :read
                :liminal.policy/relation :acme/owns}
        {db :db-after} (d/transact *connection* {:tx-data [policy]})
        rules '[[(pr-relation ?p ?r ?relation)
                 [?p :acme/owns ?r]
                 [(ground :acme/owns) ?relation]]]]
    (is (authorized? db [:acme/principal0] :read :acme/resource0 :rules rules))
    (is (not (authorized? db [:acme/principal0] :read :acme/resource1 :rules rules)))
    (is (not (authorized? db [:acme/principal1] :read :acme/resource0 :rules rules)))
    (is (not (authorized? db [:acme/principal1] :read :acme/resource1 :rules rules)))))

(deftest principal-attribute-policy
  (let [policy {:liminal.policy/permit?   true
                :liminal.policy/effectivity 0
                :liminal.policy/principal :acme/foo
                :liminal.policy/action    :read
                :liminal.policy/resource :acme/resource0}
        {db :db-after} (d/transact *connection* {:tx-data [policy]})]
    (is (authorized? db [:acme/principal0] :read :acme/resource0))
    (is (not (authorized? db [:acme/principal0] :read :acme/resource1)))
    (is (authorized? db [:acme/principal1] :read :acme/resource0))
    (is (not (authorized? db [:acme/principal1] :read :acme/resource1)))))

(deftest resource-attribute-policy
  (let [policy {:liminal.policy/permit?   true
                :liminal.policy/effectivity 0
                :liminal.policy/principal :acme/principal0
                :liminal.policy/action    :read
                :liminal.policy/resource :acme/bar}
        {db :db-after} (d/transact *connection* {:tx-data [policy]})]
    (is (authorized? db [:acme/principal0] :read :acme/resource0))
    (is (authorized? db [:acme/principal0] :read :acme/resource1))
    (is (not (authorized? db [:acme/principal1] :read :acme/resource0)))
    (is (not (authorized? db [:acme/principal1] :read :acme/resource1)))))

(deftest custom-policy-interpreter
  (let [policy {:liminal.policy/permit?   true
                :liminal.policy/effectivity 0
                :liminal.policy/action    :read
                :liminal.policy/relation :acme/X}
        {db :db-after} (d/transact *connection* {:tx-data [policy]})
        rules '[[(policy ?policy ?p ?a ?r)
                 [?policy :liminal.policy/relation :acme/X]
                 [?p :acme/foo 0]]]]
    (is (authorized? db [:acme/principal0] :read :acme/resource0 :rules rules))
    (is (authorized? db [:acme/principal0] :read :acme/resource1 :rules rules))
    (is (not (authorized? db [:acme/principal1] :read :acme/resource0 :rules rules)))
    (is (not (authorized? db [:acme/principal1] :read :acme/resource1 :rules rules)))))

(deftest effectivity-dominates
  (let [policy0        {:liminal.policy/permit?     true
                        :liminal.policy/effectivity 0
                        :liminal.policy/principal   :acme/principal0
                        :liminal.policy/action      :read
                        :liminal.policy/resource    :acme/resource0}
        policy1        {:liminal.policy/permit?     false
                        :liminal.policy/effectivity 10
                        :liminal.policy/principal   :acme/principal0
                        :liminal.policy/action      :read
                        :liminal.policy/resource    :acme/resource0}
        {db :db-after} (d/transact *connection* {:tx-data [policy0 policy1]})]
    (is (not (authorized? db [:acme/principal0] :read :acme/resource0)))
    (is (not (authorized? db [:acme/principal0] :read :acme/resource1)))
    (is (not (authorized? db [:acme/principal1] :read :acme/resource0)))
    (is (not (authorized? db [:acme/principal1] :read :acme/resource1)))))

(defn conditional-test
  [{::sut/keys [policy principals action resource] :keys [source] :as context}]
  (= "192.168.1.1" source))

(deftest conditioned-policy
  (let [policy {:liminal.policy/permit?   true
                :liminal.policy/effectivity 0
                :liminal.policy/principal :acme/principal0
                :liminal.policy/action    :write
                :liminal.policy/resource    :acme/resource0
                :liminal.policy/condition `conditional-test}
        {db :db-after} (d/transact *connection* {:tx-data [policy]})]
    (is (authorized? db [:acme/principal0] :write :acme/resource0 :context {:source "192.168.1.1"}))
    (is (not (authorized? db [:acme/principal0] :write :acme/resource0 :context {:source "192.168.1.2"})))))

(deftest list-policies-by-principal
  (let [policy0        {:liminal.policy/documentation "0"
                        :liminal.policy/permit?       true
                        :liminal.policy/effectivity   0
                        :liminal.policy/principal     :acme/foo
                        :liminal.policy/action        :read
                        :liminal.policy/resource      :acme/resource0}
        policy1        {:liminal.policy/documentation "1"
                        :liminal.policy/permit?       true
                        :liminal.policy/effectivity   0
                        :liminal.policy/principal     :acme/principal1
                        :liminal.policy/action        :delete
                        :liminal.policy/resource      :acme/resource1}
        policy2        {:liminal.policy/documentation "2"
                        :liminal.policy/permit?       true
                        :liminal.policy/effectivity   0
                        :liminal.policy/principal     :acme/principal0
                        :liminal.policy/action        :write
                        :liminal.policy/resource      :acme/bar}
        {db :db-after} (d/transact *connection* {:tx-data [policy0 policy1 policy2]})]
    (is (= #{}
           (into #{} (comp (filter (comp :liminal.policy/permit? first))
                           (map second)
                           (map :db/ident))
                 (policies db nil :annihilate nil {}))))
    (is (= #{:acme/principal0 :acme/principal1 :acme/foo}
           (into #{} (comp (filter (comp :liminal.policy/permit? first))
                           (map second)
                           (map :db/ident))
                 (policies db nil :read nil {}))))
    (is (= #{:acme/principal0 :acme/principal1 :acme/foo}
           (into #{} (comp (filter (comp :liminal.policy/permit? first))
                           (map second)
                           (map :db/ident))
                 (policies db nil :read :acme/resource0 {}))))
    (is (= #{}
           (into #{} (comp (filter (comp :liminal.policy/permit? first))
                           (map second)
                           (map :db/ident))
                 (policies db nil :read :acme/resource1 {}))))
    (is (= #{:acme/principal0 :acme/principal1 :acme/foo}
           (into #{} (comp (filter (comp :liminal.policy/permit? first))
                           (map second)
                           (map :db/ident))
                 (policies db nil nil :acme/resource0 {}))))
    (is (= #{:read :write}
           (into #{} (comp (filter (comp :liminal.policy/permit? first))
                           (map (fn [[_ _ x & _]] x)))
                 (policies db nil nil :acme/resource0 {}))))))

;; Despite the temptation, this test ensures liminal is only responsible for answering
;; "does P have authorization to do A to R?", not "does P exist?" or "does R exist?".
(deftest missing-principal
  (testing "missing principal"
    (let [db (d/db *connection*)]
      (is (thrown? Exception (authorized? db [:acme/principalX] :read :acme/resource0)))
      (is (thrown? Exception (authorized? db [[:acme/uid 99999]] :read :acme/resource0)))))
  (testing "missing resource"
    (let [db (d/db *connection*)]
      (is (thrown? Exception (authorized? db [:acme/principal0] :read :acme/resourceX)))
      (is (thrown? Exception (authorized? db [:acme/principal0] :read [:acme/pn "X"]))))))
