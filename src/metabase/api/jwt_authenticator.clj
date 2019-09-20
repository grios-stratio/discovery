(ns metabase.api.jwt-authenticator
  "lalala"
  (:require [buddy.sign.jwt :as jwt]
            [buddy.core.keys :as keys]
            [buddy.core.codecs :as codecs]
            [buddy.core.codecs.base64 :as b64]
            [clj-time.core :as time]
            [clojure.string :as str]
            [cheshire.core :as json]))

(def cert-string "-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIFnTCCA4WgAwIBAgIFFWQ5I5YwDQYJKoZIhvcNAQELBQAwaDELMAkGA1UEBhMC
RVMxDzANBgNVBAgMBk1hZHJpZDEPMA0GA1UEBwwGTWFkcmlkMQ0wCwYDVQQKDARU
ZXN0MREwDwYDVQQLDAhTZWN1cml0eTEVMBMGA1UEAwwMVGVzdCBSb290IENBMB4X
DTE5MDcyOTA5MjYzOFoXDTI5MDcyNjA5MjYzOFowUDELMAkGA1UEBhMCRVMxDzAN
BgNVBAgMBk1hZHJpZDENMAsGA1UECgwEVGVzdDERMA8GA1UECwwIU2VjdXJpdHkx
DjAMBgNVBAMMBVZhdWx0MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA
v2Pv8ApsoYdiKmak8n56No7VradpBVJkoZsRctjDnMHRDhbnNkNGCS7koYd44SZl
CKAhPZiniY88Qc8czTFLzMbbqQmXVwJxkCZCNZF6FUUPH3BInPVqGBQnaktvc3A9
frFaJP0hD2trQGxhFzeA3peRY3fMiIoaO6bKExgiokJIY7l3onJaI0yPOrS7QcHm
hqQc4TOh+Gyt3K0RW3r1rILtANAxPy/qcrkfFzLB5bWTjd6PY0A2LRmSruA3PJja
iIKD9E3c4TKINkuLhPDZViceZ0or+GNYBNLfLoqJN79LvCYGYEZEEN08hl5yMNgf
VgQrJZgVUkFBkPKmqquhDxgFLiLklf0wrJ89KDmQydb+H7GcrRfnGWSw0dpmx1ao
1EGQVy4zyOol5j+SA2r4hkNnLn585ua4omFdeipf0uBm5tiw9GRiuAsWC9IxQFj7
5+FJzppsbL5icafjDjCeybDk0ugzrmZ9q/eySgQ6yl99Lal302T5EwuXZJmgZxEh
qxvhPISrnkN6g/oSnWfzIt4dkoi6ope83jD9pr9jjJZZaK//aZnC6HQzb79u8Vcd
/wYmtsRxVBIwKnOv90r6geUg8jvKy1d9mFkw98gzNnufzBalgcJ+bo2mRTbMKpWl
3ukLuOM+pqw6Vy3sNQ/tK6HmQKwdW6fI4LD8f2+NzZ0CAwEAAaNmMGQwHQYDVR0O
BBYEFB4oDgqaHzC1O0/1XgLMA+DJLRMkMB8GA1UdIwQYMBaAFJp80JYhb27/8EOH
CexcjxDI2WH9MBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgGGMA0G
CSqGSIb3DQEBCwUAA4ICAQABOsp1JUnPyW9D9W7p6tQ4crsi/MVwXoLHewUev4c5
JKK+eDVpgsOgPO2yiYyOJeagNle2m/JI2ANibfELlxPS3MxBKel0+mBHmgzFeVLQ
909kOcRqrLCZezkAA+NXCk98wYFgKPHg7eKTfcpjQeiTMZSIcWcSAU+23uGnSdOo
L7ar/WiQAFtlymY8rn6VER+HiFoXRWZdqFI5FFjPjHYR23jR9ggAWHSHyVJsLURW
MTEkU3+2H0KWwqOfdktu9Yz8DylKRr4zzXXzygKEsD9JizJegArpWDAmbULEKuE/
nc0gmKLhdXxG6epbgb3CqNNLQeozGj7cFtDKBQgyBZMiSwDV4Js2ngtAR6g8krHl
voih8smO9Zx5IXbcwnAg/Hz2MZAI7WhBpjjDfHlMmQrqdQBiYnUhonNxAuu2Mm1+
5vO+qudm6qBqecL9B68CSpsTn8imH0cEVPmPGQzKyMVgZenM2U92iWUZitrgZYLS
BXb5KFsKAvRnG1Jwu7l8u0gTT0enbxXeUfeoc5izwGmVbR1NtxeaWr3IMrR1+nh7
8RHOCgu/NXNmwdgb7HgYUTTFwDiPWqN6m3EK6ZCnWN3jb3mMl1XdjanrK1lJlprI
tEcvi0vHqhQFv/45uAB96Rrpr9Oa+79pcYUMmVEnKjDjPoHf+gaonnklblFTE5VB
Qw==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIFtjCCA56gAwIBAgIJAPULLhlJ3P8eMA0GCSqGSIb3DQEBCwUAMGgxCzAJBgNV
BAYTAkVTMQ8wDQYDVQQIDAZNYWRyaWQxDzANBgNVBAcMBk1hZHJpZDENMAsGA1UE
CgwEVGVzdDERMA8GA1UECwwIU2VjdXJpdHkxFTATBgNVBAMMDFRlc3QgUm9vdCBD
QTAeFw0xOTA3MjkwOTI2MzdaFw0zOTA3MjQwOTI2MzdaMGgxCzAJBgNVBAYTAkVT
MQ8wDQYDVQQIDAZNYWRyaWQxDzANBgNVBAcMBk1hZHJpZDENMAsGA1UECgwEVGVz
dDERMA8GA1UECwwIU2VjdXJpdHkxFTATBgNVBAMMDFRlc3QgUm9vdCBDQTCCAiIw
DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAKjtoDSQ5NTxYu8YWUarCW4p+WfF
z8OTqVBSeR5EZ5tJTzt+zoxx65chBlYcx1PS0pNmPAr/2kX471YNSL/Z13PcEx7v
2rafb0VmMRiMRkf0Uh1oT5OpQ/BrmLCaIz2GTXccbq/C9A9i5xz/q1gKkQ81qFaO
4DfUteZgVdlG+rgwouVEwFrkpwg55EUWwpOW04yZrbOVKYzR/H+JYllgwFHV95j8
f/qkyqrRYObT6/WOvaWBdrImEEh/f+T+D4QF4VBZdjEmuOn2W+0Q4PB+7CwtPPKC
zT468QV8h1CFza9VBsnoXZJ5MmTJXjDRMXSAzL1lR0Dhok8YLYk0/gfvoCxsEBv+
1aE16l7G1rGT6NhXYbTttjH4kVkEWjE7VLO4i0/1M2CBh4HMvQontoVm3Z+nHHUm
YEY0noo+pfEO2OZ0jsTEbBxagr4QlUIZUf7MG4NnE2Kd+2dJhSvSkjcC/94DzAnH
A4vB7/Bu4e5KuXuK/JerQjeTQtvGya8+CR3wO0pc9nitoYf4/TjSwTLM94A77Heq
evV3/jNrNIcLkpz9bGohlA1qV7KnaGoHy4KPt/XLBfgh4GkZVApW75mXnp+YA4Kg
HlSI4mZErlqHkeuLoim26saXhEnfq+TFeLP86OV3ov2ClbpaGbCTht7LImhgDHPm
R+g6VFePsjt4kyyVAgMBAAGjYzBhMB0GA1UdDgQWBBSafNCWIW9u//BDhwnsXI8Q
yNlh/TAfBgNVHSMEGDAWgBSafNCWIW9u//BDhwnsXI8QyNlh/TAPBgNVHRMBAf8E
BTADAQH/MA4GA1UdDwEB/wQEAwIBhjANBgkqhkiG9w0BAQsFAAOCAgEAPkhVcC1N
JDubP3sJcc8QU4lFm8/lvYGdv48HylDZfUkKgcrp/zYNnQtgVqJiJ5eq0FusipGN
mwv1On1tdG0mEB9N9U2xLx9szAXKLQTliC8aNBCd8Y8XyH+PMev8dKv87p5bIgWI
K1AO5IoOIPdmYn5Rs+tc6zbWt+NmJayKV2y6xnPH4kkdxQH7T2qi2l24dHeeH2PZ
3G6tNVnNjbShnyeZ3KCU82sYSGTYr4RHUqbwkxty6Aapjl2AKjkLhoQDk6AbiphM
/c7JpI9qgx2jITe3wzE7QVRrXXdD8S5L2kNlY2qBhl4WqoxX/eRl8x72m/GJtNFf
s2cbOSToGK5avYafVHXiSLnvg5+vHU40lR3rI1Bxh/YUv6mj0w0jzatjG/O9M/Ls
cF53ncx+ey7qu32M0XnBgqtK565HLliOxXZ+L2h2BLPjSlZHpGmxRvTymzfP5xki
4u9gWLE8KMtxjambrx8WhuicSdALEJpvJBhwtFgFwUgqTpXHww9ReXzJeN5UBC+y
2gpmqUjL964vxvWgFeIEr9oQBpXx8BEolG+W15DfRdpg5U0xnePn98FB+kixB5B7
gnEv0+xQHAJKLvCd0QCpYRkjgfXkaZfAUbidl07QlCw/52mYt7x9Vggmc3AZBmQz
69z5I1DUyEg31iXKvzHETc22lbqovj+pLrM=
-----END CERTIFICATE-----
")


(def test-token "eyJ2YWwiOiJodHRwczpcL1wvbXByb3h5LnRlc3QuZ2w6NDQ0XC9hdXRoXC90b2tlblwvdmVyaWZ5IiwieDV1IjoiaHR0cHM6XC9cL21wcm94eS50ZXN0LmdsOjQ0NFwvYXV0aFwvdG9rZW5cL3B1YmxpYyIsImFsZyI6IlJTMjU2IiwidHlwIjoiSldUIn0.eyJuYmYiOjE1NjQ1NjYxOTAsImlhdCI6MTU2NDU2NjE5MCwiaXNzIjoibXByb3h5LnRlc3QuZ2wiLCJzcnYiOiJpbnN0YW5jaWEtMSIsImdyb3VwcyI6IkRBR0xUX1VTX0FXR1YsREFHTFRfVVNfVVpQVixEQUdMVF9VU19NQVhZLERBR0xUX1VTX1FKRUMsREFHTFRfVVNfUVpKRixEQUdMVF9VU19JR01ILERBR0xUX1VTX1JTVlEsREFHTFRfVVNfSElLWixEQUdMVF9VU19IQktWLERBR0xUX1VTX1NIRUYsREFHTFRfVVNfWUNOTyxEQUdMVF9VU19PRkRVLERBR0xUX1VTX0RGUk8sREFHTFRfVVNfUlhMQixEQUdMVF9VU19TWUtJLERBR0xUX1VTX05KVk4sREFHTFRfVVNfU1FNWixEQUdMVF9VU19KVVdSLERBR0xUX1VTX0VPT1osREFHTFRfVVNfSlpTTCxEQUdMVF9VU19ZRlJDLERBR0xUX1VTX0hFS1osREFHTFRfVVNfV0dESyxEQUdMVF9VU19XSUNZLERBR0xUX1VTX0lLSUksREFHTFRfVVNfSkxYRyxEQUdMVF9VU19XUUtFLERBR0xUX1VTX1NYQ08sREFHTFRfVVNfTE5JTyxEQUdMVF9VU19YVERGLERBR0xUX1VTX1RKSEEsREFHTFRfVVNfWkdGQSxEQUdMVF9VU19JVUxSLERBR0xUX1VTX0pRT1MsREFHTFRfVVNfV0NGTyxEQUdMVF9VU19WQUVKLERBR0xUX1VTX1NFWUssREFHTFRfVVNfRkFFRCxEQUdMVF9VU19USEJHLERBR0xUX1VTX0xNU04sREFHTFRfVVNfV05aVSxEQUdMVF9VU19VTUVYLERBR0xUX1VTX05EV0QsREFHTFRfVVNfT1hWQSxEQUdMVF9VU19DSUFULERBR0xUX1VTX0xZWUssREFHTFRfVVNfT01MUyxEQUdMVF9VU19QS1VULERBR0xUX1VTX0pLRFIsREFHTFRfVVNfQUNZTCxEQUdMVF9VU19VT0NYIiwic3ViIjoiRjgxMDY4MCIsImFwcCI6IkFSTUFESUxMTyIsInVzZXIiOiJGODEwNjgwIiwiZXhwIjoxNTY0NTY2NzkwLCJtVExTIjoibVRMU0Bsb2NhbGhvc3QifQ.T1IH_gq5h0EeK1g8vs7Hc_sjz7uqENFs4Rh2u24G4JO5C4TD8qp8P7J2fobZgPTT3J0pcGs5DL0PiGAYtAGc0rEJmtIle168k2_JLOj51otmCu4cKF36nhKCCG5BIXUqWdudbRTp8hBEnLOhyQpNjHgmFOMoJIY_-Kk2nJbDZOJ6PwLYFAkLot717y6sHUNLtkmbe_nyFDFi6AIHeii0oX0Dq9G3jBm3MbhFrWqHEtQnwSjQ5aOwxyU1q-yCJbBL_nPhYOymV5MhKDMjyEEDzCOJnpW4uAJXncNldMDVhHsO7Jlkp7Zck-0s65ecm6_ojkRqal7TaYNa52-CJZH4lBL6TTeLumJ9_0y0Dm04VoF2tgmbTL-qKlklW86NF42dRYv6i-i_GnJr0y3hp_VvIXgN0ActiqHGd6AGiUBsILYNTxInc6jGhZI53VjRlGhbTyjQHSdkXYg0HHVPjq4CzI9gHrZnWANHhpu1bvcDk55oT13CQCbuAMb-A69kkQj6pv0_gIFz3am5HBw9nkHzdd84PHOxexiiA4G77Jn9usYVptCelIHSMiqrjIWi1RgFJabUVTadjqPs3ygYRiDKZlHXTG2ezrIZa0u5TxMGeoZdN2JKvon6Rm7sn4ktsMOnjzGQF9XAIwNzbY3rcrsUhL6IJpe6nmVDekJ__4xWS0o")
(def test-headers {"Authorization" (str "bearer " test-token)})
(def public-key (keys/str->public-key cert-string))
(def fake-now (clj-time.coerce/from-long (* (- 1564566790 100) 1000)))
(def bad-header {})

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
  (-> token
      (parse-header)
      (:x5u)))


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
          {:error "Authorization header did not start with 'bearer'"}))
      {:error "Could not find Authorization header"}))


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
          pkey (if (and token (not (errors? token))) (get-verification-key token))]
      (cond
        (not token) {:error "Could not obtain verification key for jwt token"}
        (not pkey) {:error "Could not obtain jwt token from request headers"}
        (errors? token pkey) {:error (get-errors token pkey)}
        pkey (-> token
                 (verify-token pkey)
                 (select-keys [:user :groups])
                 (update-in [:groups] #(str/split % #",")))))
    (catch Exception e
      {:error (.toString e)})))



(verify-token nil public-key)
(http-header->jwt-token {})
(http-header->jwt-token test-headers)
(http-headers->user-info test-headers)
(http-headers->user-info {})
(get-verification-key (http-header->jwt-token test-headers))
(verify-token (http-header->jwt-token test-headers) (get-verification-key (http-header->jwt-token test-headers)))
