(ns monkey.oci.test.helpers
  (:require [buddy.core.keys.pem :as pem]
            [clojure.java.io :as io]
            [monkey.oci.sign :as sign])
  (:import java.net.URI
           [java.time ZonedDateTime ZoneId]
           java.util.Optional
           java.util.function.Supplier
           com.oracle.bmc.http.signing.SigningStrategy
           [com.oracle.bmc.http.signing.internal KeySupplier RequestSignerImpl]))

(defn load-privkey [src]
  (with-open [r (io/reader src)]
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
                                   (as-supplier (constantly (sign/key-id conf))))]
    (.signRequest
     signer
     (URI/create url)
     (name method)
     (update headers "date" (comp vector sign/format-time #(or % (ZonedDateTime/now (ZoneId/of "GMT")))))
     nil)))
