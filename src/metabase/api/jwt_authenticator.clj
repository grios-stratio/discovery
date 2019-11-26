(ns metabase.api.jwt-authenticator
  (:require [buddy.sign.jwt :as jwt]
            [buddy.core.keys :as keys]
            [buddy.core.codecs :as codecs]
            [buddy.core.codecs.base64 :as b64]
            [clj-time.core :as time]
            [clojure.string :as str]
            [cheshire.core :as json]
            [metabase.config :as config]))


(defn- split-token
  [token]
  (str/split token #"\." 3))


(defn- parse-data
  [^String data]
  (-> (b64/decode data)
      (codecs/bytes->str)
      (json/parse-string true)))


(defn- parse-header
  [token]
  (try
    (let [[header-b64] (split-token token)
          header (parse-data header-b64)
          alg (:alg header)]
      (cond-> header
        alg (assoc :alg (keyword (str/lower-case alg)))))
    (catch com.fasterxml.jackson.core.JsonParseException e
      (throw (ex-info "Message seems corrupt or manipulated."
               {:type :validation :cause :header})))))


(defn- parse-payload
  [token]
  (try
    (let [[_ payload] (split-token token)]
      (parse-data payload))
    (catch com.fasterxml.jackson.core.JsonParseException e
      (throw (ex-info "Message seems corrupt or manipulated."
               {:type :validation :cause :payload})))))


(defn- get-verification-key-url
  [token]
  (if-let [url (:x5u (parse-header token))]
    url
    (throw (Exception. "Could not find 'x5u' claim in token header"))))


(defn- get-alg
  [token]
  (:alg (parse-header token)))


(defn- http-header->jwt-token
  [headers]
  (let [header-name (config/config-str :jwt-header-name)]
    (if (contains? headers header-name)
      (get headers header-name)
      (throw (Exception. "Could not find Authorization header")))))

(def fake-now (clj-time.coerce/from-long (* (- 1564566790 100) 1000)))
(defn- verify-token
  [token pkey]
  (let [alg (get-alg token)]
    (jwt/unsign token pkey {:alg alg :now fake-now}))) ; TODO: remove fake date


(defn- ssl-config []
  (if (config/config-bool :jwt-insecure-request-pkey)
    {:insecure? true}
    {:trust-store (config/config-str :mb-jetty-ssl-truststore)
     :trust-store-pass (config/config-str :mb-jetty-ssl-truststore-password)}))


(defn- get-verification-key
  [url]
  (-> url
      (clj-http.client/get (ssl-config))
      (:body)
      (keys/str->public-key)))


(defn http-headers->user-info
  [headers]
  (try
    (let [username-claim (config/config-kw :jwt-usernam-claim)
          groups-claim (config/config-kw :jwt-groups-claim)
          token (http-header->jwt-token headers)
          pkey (get-verification-key (config/config-str :jwt-public-key-endpoint))]
      (cond
        (not token) {:error "Could not obtain jwt token from request headers"}
        (not pkey) {:error "Could not obtain verification key for jwt token"}
        pkey (let [info (-> token
                            (verify-token pkey)
                            (select-keys [username-claim groups-claim])
                            (update-in [groups-claim] #(str/split % #",")))]
               {:user (username-claim info) :groups (groups-claim info)})))
    (catch Exception e
      {:error (.toString e)})))
