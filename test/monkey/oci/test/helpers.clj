(ns monkey.oci.test.helpers
  (:require [buddy.core.keys.pem :as pem]
            [clojure.java.io :as io]
            [monkey.oci.sign :as sign])
  (:import java.io.StringReader
           java.net.URI
           [java.time ZonedDateTime ZoneId]
           [java.util Optional Base64]
           java.util.function.Supplier
           com.oracle.bmc.http.signing.SigningStrategy
           [com.oracle.bmc.http.signing.internal KeySupplier RequestSignerImpl]))

(defn base64-decode
  "Decodes given base64 string back into a string"
  [s]
  (-> (Base64/getDecoder)
      (.decode s)
      (String.)))

(defn- ->reader
  "If `s` points to an existing file, open it as a file reader,
   otherwise returns a string reader, assuming the contents is
   base64 encoded."
  [s]
  (if (.exists (io/file s))
    (io/reader s)
    ;; Read it, decode it, and put it back in a reader
    (StringReader. (base64-decode s))))

(defn load-privkey [src]
  (with-open [r (->reader src)]
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
