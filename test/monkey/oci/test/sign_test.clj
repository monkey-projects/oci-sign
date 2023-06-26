(ns monkey.oci.test.sign-test
  (:require [clojure.test :refer :all]
            [monkey.oci.sign :as sut]))

(deftest sign
  (testing "generates signature"
    (is (some? (sut/sign nil nil)))))

