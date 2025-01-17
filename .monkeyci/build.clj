(ns build
  (:require [monkey.ci.build.api :as api]
            [monkey.ci.plugin
             [clj :as p]
             [github :as gh]]))

;; A bit more complicated because we need to get some build params for
;; integration tests
(defn run-tests [ctx]
  (let [props (-> (api/build-params ctx)
                  (select-keys ["TENANCY_OCID" "USER_OCID" "KEY_FINGERPRINT"
                                "PRIVATE_KEY" "REGION"]))]
    (-> (p/deps-test {})
        (update :container/env merge props))))

[run-tests
 (p/deps-publish {})
 (gh/release-job
  {:dependencies ["publish"]})]
