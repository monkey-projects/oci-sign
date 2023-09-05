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
                     (get "date")))))

  (testing "adds content headers for POST"
    (let [h (sut/sign-headers {:url "http://test"
                               :method :post
                               :body "test body"
                               :headers {"content-type" "text/plain"
                                         "content-length" "9"}})]
      (is (contains? h "content-type"))
      (is (contains? h "content-length"))
      (is (contains? h "x-content-sha256"))))

  (testing "defaults to `application/json`"
    (is (= "application/json" (-> (sut/sign-headers {:url "http://test"
                                                     :method :post
                                                     :body "test"})
                                  (get "content-type")))))

  (testing "calculates `content-length` if not provided"
    (is (= "4" (-> (sut/sign-headers {:url "http://test"
                                      :method :post
                                      :body "test"})
                   (get "content-length"))))))

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
      (verify-signature (assoc req :url "http://localhost/test?key=value")))

    (testing "POST request"

      (testing "signature matches for empty body"
        (verify-signature (-> req
                              (assoc :method :post)
                              (update :headers assoc
                                      "content-type" "text/plain"
                                      "content-length" "0"))))

      (testing "signature matches for non-empty body"
        (verify-signature (assoc req
                                 :method :post
                                 :body "test body")))

      (testing "signature matches for request with content type header"
        (-> req
            (assoc :method :post
                   :body "{\"key\":\"value\"}")
            (assoc-in [:headers "content-type"] "application/json")
            (verify-signature)))

      (testing "converts headers to lowercase"
        (-> req
            (assoc :method :post
                   :body "some test")
            (assoc-in [:headers "Content-Type"] "text/plain")
            (verify-signature)))

      (testing "includes `x-content-sha256` header"
        (is (string? (as-> req x
                       (assoc x
                              :method :post
                              :body "some test")
                       (sut/sign-headers x)
                       (sut/sign conf x)
                       (get x "x-content-sha256"))))))

    (testing "signature matches for PUT request"
      (verify-signature (assoc req
                               :method :put
                               :body "Test body")))

    (testing "signature matches for PATCH request"
      (verify-signature (assoc req
                               :method :patch
                               :body "Test body")))))

(deftest merge-headers
  (testing "merges request and signature headers"
    (is (= {"date" "test-date"
            "content-type" "test-type"}
           (sut/merge-headers {"date" "test-date"}
                              {"content-type" "test-type"}))))

  (testing "signature headers have precedence"
    (is (= {"date" "test-date"
            "content-type" "signature-type"}
           (sut/merge-headers {"date" "test-date"
                               "content-type" "request-type"}
                              {"content-type" "signature-type"}))))

  (testing "keeps in mind casing differences"
    (is (= {"date" "test-date"
            "content-type" "signature-type"}
           (sut/merge-headers {"date" "test-date"
                               "Content-Type" "request-type"}
                              {"content-type" "signature-type"})))))
