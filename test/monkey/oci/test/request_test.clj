(ns monkey.oci.test.request-test
  "Request integration test"
  (:require [cheshire.core :as json]
            [clojure.test :refer :all]
            [clojure.tools.logging :as log]
            [clojure.spec.alpha :as s]
            [config.core :refer [env]]
            [monkey.oci.sign :as sign]
            [monkey.oci.test.helpers :as th]
            [org.httpkit.client :as http])
  (:import java.net.URI))

(defn env->config
  ([env]
   (-> env
       (select-keys [:tenancy-ocid :user-ocid :key-fingerprint :private-key])
       (update :private-key th/load-privkey)))
  ([]
   (env->config env)))

(defn- ->clj-map [m]
  (->> m
       (.entrySet)
       (reduce (fn [r e]
                 (assoc r (.getKey e) (.getValue e)))
               {})))

(defn execute-request [conf req]
  (let [sign-headers (sign/sign-headers req)
        headers (sign/sign conf sign-headers)]
    (log/debug "Sending request using headers" headers)
    (http/get (:url req)
              {:headers headers})))

(deftest config
  (testing "config is valid"
    (is (s/valid? ::sign/config (env->config)))))

(deftest get-request
  (testing "can execute simple GET request"
    (let [req {:url (format "https://objectstorage.%s.oraclecloud.com/n/" (:region env))
               :method :get}
          conf (env->config)
          resp @(execute-request conf req)]
      (is (some? resp))
      (is (= 200 (:status resp)))
      ;; Body must be a json string
      (is (string? (json/parse-string (:body resp)))))))
