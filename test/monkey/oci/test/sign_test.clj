(ns monkey.oci.test.sign-test
  (:require [clojure.java.io :as io]
            [clojure.test :refer :all]
            [monkey.oci.sign :as sut]
            [monkey.oci.test.helpers :as th])
  (:import java.net.URI
           [java.time ZoneId ZonedDateTime]
           java.util.Optional
           java.util.function.Supplier
           com.oracle.bmc.http.signing.SigningStrategy
           [com.oracle.bmc.http.signing.internal KeySupplier RequestSignerImpl]))

(defn load-privkey []
  (th/load-privkey (io/resource "test/test.key")))

(deftest privkey
  (testing "can load"
    (is (some? (load-privkey)))))

(deftest key-id
  (testing "constructs key id from config values"
    (is (= "a/b/c" (sut/key-id {:tenancy-ocid "a"
                                :user-ocid "b"
                                :key-fingerprint "c"})))))

(deftest sign-headers
  (testing "adds date if not provided"
    (is (string? (-> {:url "http://test"
                      :method :get}
                     (sut/sign-headers)
                     (get "date"))))))

(deftest sign
  (let [date (ZonedDateTime/of 2023 6 28 13 41 0 0 (ZoneId/of "CET"))
        conf {:private-key (load-privkey)
              :user-ocid "user-ocid"
              :tenancy-ocid "tenancy-ocid"
              :key-fingerprint "fingerprint"}
        req  {:url "http://localhost/test"
              :method :get
              :headers {"date" date}}
        verify-signature (fn [req]
                           (let [r (th/sign-java conf req)
                                 auth (get r "authorization")]
                             (is (not-empty r))
                             (is (string? auth))
                             (is (= auth (-> (sut/sign conf (sut/sign-headers req))
                                             (get "authorization"))))))]

    (testing "generates signature headers"
      (is (map? (sut/sign conf (sut/sign-headers req)))))

    (testing "signature matches reference"
      (verify-signature req))

    (testing "adds uri port"
      (verify-signature (assoc req :url "http://localhost:8080/test")))

    (testing "adds query string"
      (verify-signature (assoc req :url "http://localhost/test?key=value")))))
