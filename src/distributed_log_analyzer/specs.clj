(ns distributed_log_analyzer.specs
  "Data specs for distributed-log-analyzer (https://clojure.org/guides/spec).
  Function specs (s/fdef) live next to each defn in distributed_log_analyzer.core."
  (:require [cheshire.core :as json]
            [clojure.spec.alpha :as s]
            [clojure.spec.gen.alpha :as gen]))

;; --- Input: one log line (JSON, syslog, access log, or anything else) ---

(defn- gen-json-value []
  (gen/one-of [(gen/string-alphanumeric) (gen/large-integer)
               (gen/double* {:NaN? false :infinite? false})
               (gen/boolean) (gen/return nil)]))

(defn- gen-json-line []
  (gen/fmap (fn [[level msg [dk dv] [rk rv] ts]]
              (json/generate-string
               (cond-> {:message msg}
                 level (assoc :level level)
                 dk (assoc dk dv)
                 rk (assoc rk rv)
                 ts (assoc :timestamp ts))))
            (gen/tuple (gen/elements ["INFO" "error" "WARN" "debug" nil])
                       (gen/elements ["Server started" "Connection timeout" "Retry attempt" ""])
                       (gen/tuple (gen/elements [:duration_ms :latency_ms :duration :response_time nil])
                                  (gen-json-value))
                       (gen/tuple (gen/elements [:request_id :correlation_id :trace_id nil])
                                  (gen-json-value))
                       (gen/elements ["2024-01-15T10:00:01Z" "2024-01-15T10:00:05Z" nil]))))

(defn- gen-syslog-line []
  (gen/fmap (fn [[day host svc pid level msg kv]]
              (str "Jan " day " 10:00:0" (mod day 10) " " host " " svc
                   (when pid (str "[" pid "]")) ": " (when level (str level " ")) msg kv))
            (gen/tuple (gen/choose 1 28) (gen/elements ["web01" "db01"])
                       (gen/elements ["nginx" "postgres" "app"])
                       (gen/one-of [(gen/return nil) (gen/choose 1 99999)])
                       (gen/elements ["ERROR" "WARN" "INFO" "DEBUG" nil])
                       (gen/elements ["Request failed" "Vacuum completed" "Slow query"])
                       (gen/elements ["" " request_id:req-100" " duration:2500ms"
                                      " took=12.5ms trace_id=t-9"]))))

(defn- gen-access-line []
  (gen/fmap (fn [[ip method path status bytes tail]]
              (format "%s - - [15/Jan/2024:10:00:01 +0000] \"%s %s HTTP/1.1\" %d %s%s"
                      ip method path status bytes tail))
            (gen/tuple (gen/elements ["192.168.1.1" "10.0.0.7"]) (gen/elements ["GET" "POST"])
                       (gen/elements ["/api/users" "/health"]) (gen/choose 100 599)
                       (gen/elements ["1234" "-"])
                       (gen/elements ["" " 0.050" " 2.500 request_id=req-7"]))))

;; One line of text, as produced by clojure.string/split-lines or line-seq.
(s/def ::line-text
  (s/with-gen (s/and string? #(not (re-find #"[\r\n]" %)))
    #(gen/one-of [(gen-json-line) (gen-syslog-line) (gen-access-line) (gen/string-alphanumeric)])))

;; --- Parsed entries (the output of parse-line) ---

(defn- gen-finite-number []
  (gen/one-of [(gen/large-integer* {:min 0 :max 100000})
               (gen/double* {:min 0 :max 100000 :NaN? false :infinite? false})]))

(s/def ::finite-number
  (s/with-gen (s/and number? (fn [x] (not (NaN? x)))) gen-finite-number))

(s/def ::format #{:json :syslog :access-log :unknown})
(s/def ::level (s/nilable (s/with-gen string? #(gen/elements ["INFO" "ERROR" "WARN" "DEBUG" "UNKNOWN"]))))
;; JSON entries pass :message, :timestamp and :request-id through unchanged, so
;; they can be any JSON value (message is never nil); the generators stay realistic.
(s/def ::message (s/with-gen some? #(gen/elements ["Connection timeout" "Retry attempt"
                                                   "Server started" "GET /health 200"])))
(s/def ::timestamp (s/with-gen any? #(gen/elements ["2024-01-15T10:00:01Z" "2024-01-15T10:00:03Z"
                                                    "Jan 15 10:00:02" nil])))
(s/def ::request-id (s/with-gen any? #(gen/elements ["req-001" "req-002" "t-1" nil])))
(s/def ::duration-ms (s/nilable ::finite-number))
(s/def ::status (s/int-in 100 600))
(s/def ::raw (s/with-gen some? #(gen/string-alphanumeric)))

(s/def ::entry
  (s/keys :req-un [::format ::level ::message ::raw]
          :opt-un [::timestamp ::request-id ::duration-ms ::status]))
(s/def ::entries (s/coll-of ::entry :gen-max 15))

;; --- Analysis results ---

(s/def ::count nat-int?)
(s/def ::count-by-level (s/map-of ::level pos-int?))

(s/def ::top-error (s/keys :req-un [::message ::count]))
(s/def ::top-errors (s/coll-of ::top-error :kind vector?))

(s/def ::min ::finite-number)
(s/def ::max ::finite-number)
(s/def ::p50 ::finite-number)
(s/def ::p90 ::finite-number)
(s/def ::p95 ::finite-number)
(s/def ::p99 ::finite-number)
(s/def ::avg (s/with-gen (s/and double? (fn [x] (not (NaN? x))))
               #(gen/double* {:min 0 :max 100000 :NaN? false :infinite? false})))
(s/def ::latency
  (s/nonconforming
   (s/or :none (s/with-gen (fn [m] (= {:count 0} m)) #(gen/return {:count 0}))
         :stats (s/and (s/keys :req-un [::count ::min ::max ::avg ::p50 ::p90 ::p95 ::p99])
                       (fn [m] (pos? (:count m)))))))

(s/def ::levels ::count-by-level)
(s/def ::total-duration-ms (s/nilable double?))
(s/def ::correlation-group (s/keys :req-un [::request-id ::count ::levels ::total-duration-ms]))
(s/def ::correlation-ids (s/coll-of ::correlation-group :kind vector?))
(s/def ::correlation-trace (s/coll-of ::entry :kind vector?))

(s/def ::total nat-int?)
;; The full "analyze" result, which format-text-report renders.
(s/def ::report (s/keys :req-un [::total ::count-by-level ::top-errors ::latency ::correlation-ids]))
;; Any analyze result: the full report or one sub-command's key.
(s/def ::analysis (s/keys :opt-un [::total ::count-by-level ::top-errors ::latency
                                   ::correlation-trace ::correlation-ids]))

;; --- Options ---

(defn- gen-ts-bound [] (gen/elements ["2024-01-15T10:00:02Z" "2024-01-15T10:00:04Z" "Jan 15"]))
(s/def ::after (s/nilable (s/with-gen string? gen-ts-bound)))
(s/def ::before (s/nilable (s/with-gen string? gen-ts-bound)))
(s/def ::time-window (s/keys :opt-un [::after ::before]))

(s/def ::n nat-int?)
(s/def ::top-errors-opts (s/keys :opt-un [::n]))

;; -main passes the CLI --command through; unknown commands mean "analyze".
(s/def ::command
  (s/with-gen string? #(gen/elements ["analyze" "count-by-level" "top-errors"
                                      "latency-percentiles" "correlation-trace" "bogus"])))
(s/def ::correlation-id (s/nilable (s/with-gen string? #(gen/elements ["req-001" "req-002" "nope"]))))
(s/def ::top nat-int?)
(s/def ::analyze-opts (s/keys :opt-un [::command ::correlation-id ::top]))
