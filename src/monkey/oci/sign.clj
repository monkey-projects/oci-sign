(ns monkey.oci.sign
  (:require [clojure.string :as cs]
            [clojure.spec.alpha :as s]
            [buddy.sign.compact :as c])
  (:import [java.net URI URLEncoder]
           java.nio.charset.StandardCharsets))

(def private-key? (partial instance? java.security.PrivateKey))

(s/def ::tenancy-ocid string?)
(s/def ::user-ocid string?)
(s/def ::key-fingerprint string?)
(s/def ::private-key private-key?)

(s/def ::config (s/keys :req-un [::tenancy-ocid
                                 ::user-ocid
                                 ::key-fingerprint
                                 ::private-key]))

(defn key-id [conf]
  (->> [:tenancy-ocid :user-ocid :key-fingerprint]
       (map (partial get conf))
       (cs/join "/")))

(defn- url-encode [s]
  (URLEncoder/encode s StandardCharsets/UTF_8))

(defn sign-headers
  "Builds signing headers from the request"
  [{:keys [url method] :as req}]
  (let [uri (URI/create url)]
    {"date" (first (get-in req [:headers "date"]))
     "(request target)" (url-encode (str (name method) " " (.getPath uri)))
     "host" (.getHost uri)}))

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
        signature (c/sign v (:private-key conf) {:alg :ps256})
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
