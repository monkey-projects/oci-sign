(ns monkey.oci.test.sign-test
  (:require [buddy.core.keys.pem :as pem]
            [clojure.java.io :as io]
            [clojure.test :refer :all]
            [monkey.oci.sign :as sut])
  (:import java.net.URI
           [java.time ZoneId ZonedDateTime]
           java.util.Optional
           java.util.function.Supplier
           com.oracle.bmc.http.signing.SigningStrategy
           [com.oracle.bmc.http.signing.internal KeySupplier RequestSignerImpl]))

(defn load-privkey []
  (with-open [r (-> (io/resource "test/test.key")
                    (io/reader))]
    (pem/read-privkey r nil)))

(defn- as-key-supplier [f]
  (reify KeySupplier
    (supplyKey [_ _]
      (Optional/of (f)))))

(defn- as-supplier [f]
  (reify Supplier
    (get [_]
      (f))))

(defn sign-java
  "Generates a signature using the Oracle Java library.  This is used
   as a reference to compare our own signatures against."
  [conf {:keys [url method headers]}]
  (let [signer (RequestSignerImpl. (as-key-supplier (constantly (:private-key conf)))
                                   SigningStrategy/EXCLUDE_BODY
                                   (as-supplier (constantly (sut/key-id conf))))]
    (.signRequest
     signer
     (URI/create url)
     (name method)
     (update headers "date" (comp vector sut/format-time))
     nil)))

(deftest privkey
  (testing "can load"
    (is (some? (load-privkey)))))

(deftest key-id
  (testing "constructs key id from config values"
    (is (= "a/b/c" (sut/key-id {:tenancy-ocid "a"
                                :user-ocid "b"
                                :key-fingerprint "c"})))))

(deftest sign
  (let [date (ZonedDateTime/of 2023 6 28 13 41 0 0 (ZoneId/of "CET"))
        conf {:private-key (load-privkey)
              :user-ocid "user-ocid"
              :tenancy-ocid "tenancy-ocid"
              :key-fingerprint "fingerprint"}
        req  {:url "http://localhost/test"
              :method :get
              :headers {"date" date}}]
    
    (testing "generates signature"
      (is (string? (sut/sign conf (sut/sign-headers req)))))

    (testing "signature matches reference"
      (let [r (sign-java conf req)
            auth (get r "authorization")]
        (is (not-empty r))
        (is (string? auth))
        (is (= auth (sut/sign conf (sut/sign-headers req))))))))
