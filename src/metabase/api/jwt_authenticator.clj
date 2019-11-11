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
  (if (contains? headers "Authorization")
      (let [auth-header (get headers "Authorization")
            [bearer token] (str/split auth-header #" " 2)]
        (if (= (str/lower-case bearer) "bearer")
          token
          (throw (Exception. "Authorization header did not start with 'bearer'"))))
      (throw (Exception. "Could not find Authorization header"))))


(defn- verify-token
  [token pkey]
  (let [alg (get-alg token)]
    (jwt/unsign token pkey {:alg alg :now fake-now}))) ; TODO: remove fake date


(defn- get-verification-key
  [token]
  (-> token
      (get-verification-key-url)
      ((fn [x] "http://localhost:5000/auth/token/public")) ;; change actual url by our mock TODO: remove
      (clj-http.client/get) ;; TODO: check how do we use this with TLS
      (:body)
      (keys/str->public-key)))


(defn- errors?
  [& rest]
  (not-empty (filter :error rest)))


(defn- get-errors
  [& rest]
  (->> rest
       (filter :error)
       (map #(str (:error %)))
       (interleave (repeat "; "))
       (drop 1)
       (apply str)))


(defn http-headers->user-info
  [headers]
  (try
    (let [token (http-header->jwt-token headers)
          pkey (if token (get-verification-key token))]
      (cond
        (not token) {:error "Could not obtain jwt token from request headers"}
        (not pkey) {:error "Could not obtain verification key for jwt token"}
        pkey (-> token
                 (verify-token pkey)
                 (select-keys [:user :groups])
                 (update-in [:groups] #(str/split % #",")))))
    (catch Exception e
      {:error (.toString e)})))
