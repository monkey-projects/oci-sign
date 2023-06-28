(ns monkey.oci.sign
  (:require [clojure.string :as cs]
            [clojure.spec.alpha :as s]
            [buddy.sign.compact :as c])
  (:import [java.net URI URLEncoder]
           java.util.Base64
           java.nio.charset.StandardCharsets
           com.oracle.bmc.http.signing.internal.SignatureSigner))

(def private-key? (partial instance? java.security.PrivateKey))

(s/def ::tenancy-ocid string?)
(s/def ::user-ocid string?)
(s/def ::key-fingerprint string?)
(s/def ::private-key private-key?)

(s/def ::config (s/keys :req-un [::tenancy-ocid
                                 ::user-ocid
                                 ::key-fingerprint
                                 ::private-key]))

(def charset StandardCharsets/UTF_8)

(defn key-id [conf]
  (->> [:tenancy-ocid :user-ocid :key-fingerprint]
       (map (partial get conf))
       (cs/join "/")))

(defn- url-encode [s]
  (URLEncoder/encode s charset))

(defn sign-headers
  "Builds signing headers from the request"
  [{:keys [url method] :as req}]
  (let [uri (URI/create url)]
    {"date" (first (get-in req [:headers "date"]))
     ;; TODO Add query string
     "(request-target)" (str (name method) " " (.getRawPath uri))
     ;; TODO Add port
     "host" (.getHost uri)}))

(defn- generate-signature [s pk]
  #_(c/sign s pk {:alg :ps256})
  (let [signer (SignatureSigner.)
        enc (Base64/getEncoder)]
    (->> (.sign signer pk (.getBytes s charset) "SHA256withRSA")
         (.encode enc)
         (String.))))
        

(defn sign
  "Signs a request by calculating a signature based on the given config."
  [conf headers]
  (let [h (->> (keys headers)
               (cs/join " "))
        v (->> headers
               (reduce-kv (fn [r k v]
                            (conj r (str k ": " v)))
                          [])
               (cs/join "\n"))
        signature (generate-signature v (:private-key conf))
        m {"headers" h
           "keyId" (key-id conf)
           "algorithm" "rsa-sha256"
           "signature" signature
           "version" "1"}]
    (->> m
         (reduce-kv (fn [r k v]
                      (conj r (str k "=\"" v "\"")))
                    [])
         (cs/join ",")
         (str "Signature "))))
