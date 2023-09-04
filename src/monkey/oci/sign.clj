(ns monkey.oci.sign
  (:require [clojure.string :as cs]
            [clojure.spec.alpha :as s]
            [clojure.tools.logging :as log])
  (:import [java.net URI URLEncoder]
           java.time.format.DateTimeFormatter
           [java.time ZonedDateTime ZoneId]
           java.util.Base64
           [java.nio.charset Charset StandardCharsets]
           [java.security MessageDigest Signature]
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

(defn- base64-encode [^"[B" s]
  (-> (Base64/getEncoder)
      (.encode s)
      (String. charset)))

(defn- calc-content-sha256 [{:keys [^String body]}]
  ;; TODO Handle input streams or other body forms
  (let [body (or body "")]
    (when (string? body)
      (-> (MessageDigest/getInstance "SHA-256")
          (.digest (.getBytes body charset))
          (base64-encode)))))

(defn- add-body-headers [h req]
  (let [ct-header "content-type"
        cl-header "content-length"
        default-header (fn [k f]
                         (fn [in]
                           (cond-> in
                             (nil? (get in k)) (assoc k (f)))))
        default-content-type (default-header ct-header (constantly "application/json"))
        default-content-length (default-header cl-header #(str (count (:body req))))]
    (-> h
        (merge (-> req
                   :headers
                   (select-keys [cl-header ct-header])))
        ;; Default headers, in case they are missing
        (default-content-length)
        (default-content-type)
        ;; Calculate the content hash
        (assoc "x-content-sha256" (calc-content-sha256 req)))))

(defn sign-headers
  "Builds signing headers from the request"
  [{:keys [url method] :as req}]
  (let [uri (URI/create url)]
    (cond->
        {"date" (-> (or (get-in req [:headers "date"])
                        ;; Timezone must be GMT!
                        (ZonedDateTime/now (ZoneId/of "GMT")))
                    (format-time))
         "(request-target)" (str (name method) " " (format-path uri))
         "host" (format-host uri)}
      (#{:post :put :patch} method)
      (add-body-headers req))))

(defn- generate-signature
  "Generates the signature for the string using the given private key."
  [^String s ^RSAPrivateKey pk]
  (->> (doto (Signature/getInstance "SHA256withRSA")
         (.initSign pk)
         (.update (.getBytes s charset)))
       (.sign)
       (base64-encode)))

(defn sign
  "Signs a request by calculating a signature based on the given config.
   Returns the headers you should include in your request."
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
    (log/debug "Generating signature based on headers" headers)
    (->> m
         (reduce-kv (fn [r k v]
                      (conj r (str k "=\"" v "\"")))
                    [])
         (cs/join ",")
         (str "Signature ")
         (assoc (select-keys headers ["date" "content-type" "content-length"]) "authorization"))))
