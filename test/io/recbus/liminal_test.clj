(ns io.recbus.liminal-test
  (:require [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.test :refer [deftest is use-fixtures]]
            [datomic.client.api :as d]
            [datomic.local :as dl]
            [io.recbus.liminal :refer [authorized? evaluate] :as sut])
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
                 "io/recbus/liminal/baseline-roles.edn"
                 "io/recbus/liminal/baseline-policies.edn"]]
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
  (let [policy {:st.authz.policy/permit?   true
                :st.authz.policy/effectivity 0
                :st.authz.policy/principal :acme/principal0
                :st.authz.policy/action    :read
                :st.authz.policy/resource  :acme/resource0}
        {db :db-after} (d/transact *connection* {:tx-data [policy]})]
    (is (authorized? db [:acme/principal0] :read :acme/resource0))
    (is (not (authorized? db [:acme/principal0] :read :acme/resource1)))
    (is (not (authorized? db [:acme/principal1] :read :acme/resource0)))
    (is (not (authorized? db [:acme/principal1] :read :acme/resource1)))))

(deftest wildcard-principal-policy
  (let [policy {:st.authz.policy/permit?   true
                :st.authz.policy/effectivity 0
                :st.authz.policy/principal :st.authz.principal/*
                :st.authz.policy/action    :read
                :st.authz.policy/resource  :acme/resource0}
        {db :db-after} (d/transact *connection* {:tx-data [policy]})]
    (is (authorized? db [:acme/principal0] :read :acme/resource0))
    (is (not (authorized? db [:acme/principal0] :read :acme/resource1)))
    (is (authorized? db [:acme/principal1] :read :acme/resource0))
    (is (not (authorized? db [:acme/principal1] :read :acme/resource1)))))

(deftest wildcard-action-policy
  (let [policy {:st.authz.policy/permit?   true
                :st.authz.policy/effectivity 0
                :st.authz.policy/principal :acme/principal0
                :st.authz.policy/action    :st.authz.action/*
                :st.authz.policy/resource  :acme/resource0}
        {db :db-after} (d/transact *connection* {:tx-data [policy]})]
    (is (authorized? db [:acme/principal0] :read :acme/resource0))
    (is (not (authorized? db [:acme/principal0] :read :acme/resource1)))
    (is (not (authorized? db [:acme/principal1] :read :acme/resource0)))
    (is (not (authorized? db [:acme/principal1] :read :acme/resource1)))))

(deftest wildcard-resource-policy
  (let [policy {:st.authz.policy/permit?   true
                :st.authz.policy/effectivity 0
                :st.authz.policy/principal :acme/principal0
                :st.authz.policy/action    :read
                :st.authz.policy/resource  :st.authz.resource/*}
        {db :db-after} (d/transact *connection* {:tx-data [policy]})]
    (is (authorized? db [:acme/principal0] :read :acme/resource0))
    (is (authorized? db [:acme/principal0] :read :acme/resource1))
    (is (not (authorized? db [:acme/principal1] :read :acme/resource0)))
    (is (not (authorized? db [:acme/principal1] :read :acme/resource1)))))

(deftest principal-descendant-policy
  (let [policy {:st.authz.policy/permit?   true
                :st.authz.policy/effectivity 0
                :st.authz.policy/principal :acme/principal1
                :st.authz.policy/action    :read
                :st.authz.policy/resource  :acme/resource0}
        {db :db-after} (d/transact *connection* {:tx-data [policy]})]
    (is (authorized? db [:acme/principal0] :read :acme/resource0))
    (is (not (authorized? db [:acme/principal0] :read :acme/resource1)))
    (is (authorized? db [:acme/principal1] :read :acme/resource0))
    (is (not (authorized? db [:acme/principal1] :read :acme/resource1)))))

(deftest principal-resource-relation-policy
  (let [policy {:st.authz.policy/permit?   true
                :st.authz.policy/effectivity 0
                :st.authz.policy/action    :read
                :st.authz.policy/relation :acme/owns}
        {db :db-after} (d/transact *connection* {:tx-data [policy]})
        rules '[[(pr-relation ?p ?r ?relation)
                 [?p :acme/owns ?r]
                 [(ground :acme/owns) ?relation]]]]
    (is (authorized? db [:acme/principal0] :read :acme/resource0 :rules rules))
    (is (not (authorized? db [:acme/principal0] :delete :acme/resource0 :rules rules)))
    (is (not (authorized? db [:acme/principal0] :read :acme/resource0)))
    (is (not (authorized? db [:acme/principal0] :read :acme/resource1)))
    (is (not (authorized? db [:acme/principal1] :read :acme/resource0)))
    (is (not (authorized? db [:acme/principal1] :read :acme/resource1)))))

(deftest custom-policy-interpreter
  (let [policy {:st.authz.policy/permit?   true
                :st.authz.policy/effectivity 0
                :st.authz.policy/action    :write
                :st.authz.policy/relation :acme/X}
        {db :db-after} (d/transact *connection* {:tx-data [policy]})
        rules '[[(policy ?policy ?p ?a ?r)
                 [?policy :st.authz.policy/relation :acme/X]
                 [?r :acme/foo]]]]
    (is (authorized? db [:acme/principal0] :write :acme/resource0 :rules rules))
    (is (authorized? db [:acme/principal1] :write :acme/resource0 :rules rules))
    (is (not (authorized? db [:acme/principal0] :write :acme/resource1 :rules rules)))
    (is (not (authorized? db [:acme/principal0] :read :acme/resource0)))
    (is (not (authorized? db [:acme/principal0] :read :acme/resource1)))
    (is (not (authorized? db [:acme/principal1] :read :acme/resource0)))
    (is (not (authorized? db [:acme/principal1] :read :acme/resource1)))))

(deftest effectivity-dominates
  (let [policy0        {:st.authz.policy/permit?     true
                        :st.authz.policy/effectivity 0
                        :st.authz.policy/principal   :acme/principal0
                        :st.authz.policy/action      :read
                        :st.authz.policy/resource    :acme/resource0}
        policy1        {:st.authz.policy/permit?     false
                        :st.authz.policy/effectivity 10
                        :st.authz.policy/principal   :acme/principal0
                        :st.authz.policy/action      :read
                        :st.authz.policy/resource    :acme/resource0}
        {db :db-after} (d/transact *connection* {:tx-data [policy0 policy1]})]
    (is (not (authorized? db [:acme/principal0] :read :acme/resource0)))
    (is (not (authorized? db [:acme/principal0] :read :acme/resource1)))
    (is (not (authorized? db [:acme/principal1] :read :acme/resource0)))
    (is (not (authorized? db [:acme/principal1] :read :acme/resource1)))))

(defn conditional-test
  [{::sut/keys [policy principals action resource] :keys [source] :as context}]
  (= "192.168.1.1" source))

(deftest conditioned-policy
  (let [policy {:st.authz.policy/permit?   true
                :st.authz.policy/effectivity 0
                :st.authz.policy/principal :acme/principal0
                :st.authz.policy/action    :write
                :st.authz.policy/resource    :acme/resource0
                :st.authz.policy/condition `conditional-test}
        {db :db-after} (d/transact *connection* {:tx-data [policy]})]
    (is (authorized? db [:acme/principal0] :write :acme/resource0 :context {:source "192.168.1.1"}))
    (is (not (authorized? db [:acme/principal0] :write :acme/resource0 :context {:source "192.168.1.2"})))))
