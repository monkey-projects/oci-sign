(ns monkey.oci.sign
  (:require [clojure.string :as cs]
            [clojure.spec.alpha :as s])
  (:import [java.net URI URLEncoder]
           java.time.format.DateTimeFormatter
           java.time.ZonedDateTime
           java.util.Base64
           [java.nio.charset Charset StandardCharsets]
           [java.security Signature]
           java.security.interfaces.RSAPrivateKey))

;; Enable reflection warnings cause we want to use this in GraalVM native images
(set! *warn-on-reflection* true)

(def private-key? (partial instance? java.security.PrivateKey))

(s/def ::tenancy-ocid string?)
(s/def ::user-ocid string?)
(s/def ::key-fingerprint string?)
(s/def ::private-key private-key?)

(s/def ::config (s/keys :req-un [::tenancy-ocid
                                 ::user-ocid
                                 ::key-fingerprint
                                 ::private-key]))

(def ^Charset charset StandardCharsets/UTF_8)

(defn key-id [conf]
  (->> [:tenancy-ocid :user-ocid :key-fingerprint]
       (map (partial get conf))
       (cs/join "/")))

(defn- url-encode [^String s]
  (URLEncoder/encode s charset))

(def ^DateTimeFormatter time-format DateTimeFormatter/RFC_1123_DATE_TIME)

(defn format-time [^ZonedDateTime t]
  (.format time-format t))

(defn- format-path
  "Builds the path and query string for the uri"
  [^URI uri]
  (let [q (some-> (.getRawQuery uri)
                  (.trim))]
    (cond-> (.getRawPath uri)
      (not-empty q) (str "?" q))))

(defn- format-host
  "Builds host:port"
  [^URI uri]
  (let [port (.getPort uri)]
    (cond-> (.getHost uri)
      (pos? port) (str ":" port))))

(defn sign-headers
  "Builds signing headers from the request"
  [{:keys [url method] :as req}]
  (let [uri (URI/create url)]
    ;; TODO Add request body, depending on the method
    {"date" (-> (or (get-in req [:headers "date"])
                    (ZonedDateTime/now))
                (format-time))
     "(request-target)" (str (name method) " " (format-path uri))
     "host" (format-host uri)}))

(defn- generate-signature
  "Generates the signature for the string using the given private key."
  [^String s ^RSAPrivateKey pk]
  (let [enc (Base64/getEncoder)]
    (->> (doto (Signature/getInstance "SHA256withRSA")
           (.initSign pk)
           (.update (.getBytes s charset)))
         (.sign)
         (.encode enc)
         (String.))))        

(defn sign
  "Signs a request by calculating a signature based on the given config.
   Returns the value of the `authorization` header, to include in your request."
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
