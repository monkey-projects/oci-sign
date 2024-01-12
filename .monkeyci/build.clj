(ns sign.build
  (:require [monkey.ci.build
             [api :as api]
             [core :as bc]]
            [monkey.ci.plugin.clj :as p]))

;; A bit more complicated because we need to get some build params for
;; integration tests
(defn test [ctx]
  (let [props (-> (api/build-params ctx)
                  (select-keys ["TENANCY_OCID" "USER_OCID" "KEY_FINGERPRINT"
                                "PRIVATE_KEY" "REGION"]))]
    (-> (p/deps-test {})
        (update :container/env merge props))))

(bc/defpipeline build
  [test
   (p/deps-publish {})])
