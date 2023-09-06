(ns monkey.oci.test.sign.martian-test
  (:require [clojure.test :refer :all]
            [monkey.oci.sign :as sign]
            [monkey.oci.sign.martian :as sut]
            [monkey.oci.test.helpers :as th]))

(defn load-privkey []
  (th/load-privkey (clojure.java.io/resource "test/test.key")))

(deftest signer
  (testing "is a martian interceptor"
    (let [s (sut/signer {})]
      (is (map? s))
      (is (contains? s :name))
      (is (contains? s :enter))
      (is (fn? (:enter s)))))

  (let [conf {:private-key (load-privkey)
              :user-ocid "test-user"
              :tenancy-ocid "test-tenancy"
              :key-fingerprint "test-fingerprint"}
        s (sut/signer conf)]

    (testing "adds authorization header to request"
      (is (some? (-> {:request {:url "http://localhost/test"
                                :method :get}}
                     ((:enter s))
                     (get-in [:request :headers "authorization"])))))

    (testing "takes query params into account"
      (is (= (-> {:request {:url "http://localhost/test"
                            :method :get
                            :query-params {:key "value"}}}
                 ((:enter s))
                 (get-in [:request :headers]))
             (sign/sign conf (sign/sign-headers {:method :get
                                                 :url "http://localhost/test?key=value"})))))

    (testing "excludes body if configured"
      (let [s (sut/signer (assoc conf :exclude-body? (constantly true)))]
        (is (= (-> {:request {:url "http://localhost/test"
                              :method :put
                              :body "test body"}}
                   ((:enter s))
                   (get-in [:request :headers]))
               (sign/sign conf (sign/sign-headers {:method :put
                                                   :url "http://localhost/test"}
                                                  true))))))))
