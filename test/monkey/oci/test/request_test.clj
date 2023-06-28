(ns monkey.oci.test.request-test
  "Request integration test"
  (:require [clojure.test :refer :all]
            [clojure.spec.alpha :as s]
            [config.core :refer [env]]
            [monkey.oci.sign :as sign]
            [monkey.oci.test.helpers :as th]
            [org.httpkit.client :as http]))

(defn env->config
  ([env]
   (-> env
       (select-keys [:tenancy-ocid :user-ocid :key-fingerprint :private-key])
       (update :private-key th/load-privkey)))
  ([]
   (env->config env)))

(deftest config
  (testing "config is valid"
    (is (s/valid? ::sign/config (env->config)))))

(deftest get-request
  (testing "can execute simple GET request"
    (let [req {:uri "http://test"
               :method :get}
          conf (env->config)]
      (is (some? conf)))))
