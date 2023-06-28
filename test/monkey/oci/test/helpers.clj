(ns monkey.oci.test.helpers
  (:require [buddy.core.keys.pem :as pem]
            [clojure.java.io :as io]))

(defn load-privkey [src]
  (with-open [r (io/reader src)]
    (pem/read-privkey r nil)))
