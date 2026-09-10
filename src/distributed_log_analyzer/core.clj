(ns distributed_log_analyzer.core
  (:require [babashka.cli :as cli]
            [babashka.fs :as fs]
            [clojure.spec.alpha :as s]
            [clojure.string :as str]
            [cheshire.core :as json]
            [distributed_log_analyzer.specs :as specs]))

;;; --- Log Parsing ---

(defn parse-json-line [line]
  (try
    (let [m (json/parse-string line true)]
      (when (map? m)
        {:format :json
         :timestamp (or (:timestamp m) (:time m) (get m (keyword "@timestamp")))
         :level (some-> (or (:level m) (:severity m) (:log_level m))
                        str str/upper-case)
         :message (or (:message m) (:msg m) (:error m) "")
         :request-id (or (:request_id m) (:correlation_id m)
                         (:trace_id m) (:x_request_id m))
         :duration-ms (some #(when (number? %) %)
                            [(:duration_ms m) (:latency_ms m) (:duration m) (:response_time m)])
         :raw m}))
    (catch Exception _ nil)))

(s/fdef parse-json-line
  :args (s/cat :line ::specs/line-text)
  :ret (s/nilable ::specs/entry)
  :fn (fn [{ret :ret}] (or (nil? ret) (= :json (:format ret)))))

(def syslog-pattern
  #"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s+(?:(DEBUG|INFO|NOTICE|WARNING|WARN|ERROR|CRIT|ALERT|EMERG)\s+)?(.*)$")

(defn parse-syslog-line [line]
  (when-let [m (re-matches syslog-pattern line)]
    (let [[_ timestamp host service pid level message] m]
      {:format :syslog
       :timestamp timestamp
       :level (or (some-> level str/upper-case) "INFO")
       :message (str/trim message)
       :host host
       :service service
       :pid pid
       :request-id (second (re-find #"(?:request_id|correlation_id|trace_id)[=:](\S+)" message))
       :duration-ms (when-let [d (second (re-find #"(?:duration|latency|took)[=:](\d+(?:\.\d+)?)\s*ms" message))]
                      (Double/parseDouble d))
       :raw line})))

(s/fdef parse-syslog-line
  :args (s/cat :line ::specs/line-text)
  :ret (s/nilable ::specs/entry)
  :fn (fn [{ret :ret}] (or (nil? ret) (= :syslog (:format ret)))))

(def access-log-pattern
  #"^(\S+)\s+(\S+)\s+(\S+)\s+\[([^\]]+)\]\s+\"(\S+)\s+(\S+)\s+(\S+)\"\s+(\d{3})\s+(\d+|-)\s*(.*)$")

(defn parse-access-log-line [line]
  (when-let [m (re-matches access-log-pattern line)]
    (let [[_ ip _ _ timestamp method path _ status _ rest] m
          status-code (Integer/parseInt status)
          level (cond
                  (>= status-code 500) "ERROR"
                  (>= status-code 400) "WARN"
                  :else "INFO")
          duration (when (and rest (not (str/blank? rest)))
                     (when-let [d (re-find #"\d+\.\d+" (str/trim rest))]
                       (* (Double/parseDouble d) 1000)))]
      {:format :access-log
       :timestamp timestamp
       :level level
       :message (str method " " path " " status)
       :method method
       :path path
       :status status-code
       :ip ip
       :request-id (when rest (second (re-find #"(?:request_id|x_request_id)[=:](\S+)" rest)))
       :duration-ms duration
       :raw line})))

(s/fdef parse-access-log-line
  :args (s/cat :line ::specs/line-text)
  :ret (s/nilable ::specs/entry)
  :fn (fn [{ret :ret}] (or (nil? ret) (= :access-log (:format ret)))))

(defn parse-line [line]
  (let [trimmed (str/trim line)]
    (when-not (str/blank? trimmed)
      (or (parse-json-line trimmed)
          (parse-syslog-line trimmed)
          (parse-access-log-line trimmed)
          {:format :unknown
           :message trimmed
           :level "UNKNOWN"
           :raw line}))))

(s/fdef parse-line
  :args (s/cat :line ::specs/line-text)
  :ret (s/nilable ::specs/entry)
  :fn (fn [{{:keys [line]} :args ret :ret}]
        (= (nil? ret) (str/blank? line))))

;;; --- Analysis ---

(defn count-by-level [entries]
  (frequencies (map :level entries)))

(s/fdef count-by-level
  :args (s/cat :entries ::specs/entries)
  :ret ::specs/count-by-level
  :fn (fn [{{:keys [entries]} :args ret :ret}]
        (= (count entries) (reduce + 0 (vals ret)))))

(defn top-errors [entries & [{:keys [n] :or {n 10}}]]
  (->> entries
       (filter #(= "ERROR" (:level %)))
       (group-by :message)
       (map (fn [[msg es]] {:message msg :count (count es)}))
       (sort-by :count >)
       (take n)
       vec))

(s/fdef top-errors
  :args (s/cat :entries ::specs/entries :opts (s/? (s/nilable ::specs/top-errors-opts)))
  :ret ::specs/top-errors
  :fn (fn [{{:keys [opts]} :args ret :ret}]
        (and (<= (count ret) (or (:n opts) 10))
             (or (empty? ret) (apply >= (map :count ret))))))

(defn latency-percentiles [entries]
  (let [durations (->> entries
                       (keep :duration-ms)
                       sort
                       vec)]
    (if (empty? durations)
      {:count 0}
      (let [n (count durations)
            pct (fn [p] (nth durations (min (dec n) (int (Math/floor (* p (dec n)))))))]
        {:count n
         :min (first durations)
         :max (last durations)
         :avg (double (/ (reduce + 0.0 durations) n))
         :p50 (pct 0.5)
         :p90 (pct 0.9)
         :p95 (pct 0.95)
         :p99 (pct 0.99)}))))

(s/fdef latency-percentiles
  :args (s/cat :entries ::specs/entries)
  :ret ::specs/latency
  :fn (fn [{{:keys [entries]} :args ret :ret}]
        (and (= (count (keep :duration-ms entries)) (:count ret))
             (or (zero? (:count ret))
                 (<= (:min ret) (:p50 ret) (:p90 ret) (:p95 ret) (:p99 ret) (:max ret))))))

(defn correlation-id-trace [entries id]
  (->> entries
       (filter #(= id (:request-id %)))
       vec))

(s/fdef correlation-id-trace
  :args (s/cat :entries ::specs/entries :id ::specs/request-id)
  :ret ::specs/correlation-trace
  :fn (fn [{{:keys [entries id]} :args ret :ret}]
        (and (<= (count ret) (count entries))
             (every? #(= id (:request-id %)) ret))))

(defn group-by-correlation [entries]
  (->> entries
       (filter :request-id)
       (group-by :request-id)
       (map (fn [[id es]]
              {:request-id id
               :count (count es)
               :levels (frequencies (map :level es))
               :total-duration-ms (when-let [ds (seq (keep :duration-ms es))]
                                    (reduce + 0.0 ds))}))
       (sort-by :count >)
       vec))

(s/fdef group-by-correlation
  :args (s/cat :entries ::specs/entries)
  :ret ::specs/correlation-ids
  :fn (fn [{{:keys [entries]} :args ret :ret}]
        (and (= (count (filter :request-id entries)) (reduce + 0 (map :count ret)))
             (or (empty? ret) (apply >= (map :count ret))))))

;;; --- Time Filtering ---

(defn in-time-range? [entry {:keys [after before]}]
  (let [ts (:timestamp entry)]
    (if (nil? ts)
      true
      (and (or (nil? after) (>= (compare (str ts) (str after)) 0))
           (or (nil? before) (<= (compare (str ts) (str before)) 0))))))

(s/fdef in-time-range?
  :args (s/cat :entry ::specs/entry :window ::specs/time-window)
  :ret boolean?
  :fn (fn [{{:keys [entry]} :args ret :ret}]
        (or (some? (:timestamp entry)) ret)))

;;; --- Output ---

(defn format-text-report [{:keys [total count-by-level top-errors latency correlation-ids]}]
  (let [sb (StringBuilder.)]
    (.append sb (format "=== Log Analysis Report ===\nTotal entries: %d\n\n" total))

    (.append sb "--- Log Levels ---\n")
    (doseq [[level cnt] (sort-by val > count-by-level)]
      (.append sb (format "  %-10s %d\n" level cnt)))

    (when (seq top-errors)
      (.append sb "\n--- Top Errors ---\n")
      (doseq [{:keys [message count]} top-errors]
        (.append sb (format "  [%d] %s\n" count message))))

    (when latency
      (.append sb "\n--- Latency Percentiles ---\n")
      (if (pos? (:count latency))
        (do
          (.append sb (format "  Count: %d\n" (:count latency)))
          (.append sb (format "  Min:   %.2f ms\n" (double (:min latency))))
          (.append sb (format "  P50:   %.2f ms\n" (double (:p50 latency))))
          (.append sb (format "  P90:   %.2f ms\n" (double (:p90 latency))))
          (.append sb (format "  P95:   %.2f ms\n" (double (:p95 latency))))
          (.append sb (format "  P99:   %.2f ms\n" (double (:p99 latency))))
          (.append sb (format "  Max:   %.2f ms\n" (double (:max latency))))
          (.append sb (format "  Avg:   %.2f ms\n" (double (:avg latency)))))
        (.append sb "  No latency data found\n")))

    (when (seq correlation-ids)
      (.append sb "\n--- Correlation IDs (top 20) ---\n")
      (doseq [{:keys [request-id count levels total-duration-ms]} (take 20 correlation-ids)]
        (.append sb (format "  %s  entries=%d  levels=%s%s\n"
                            request-id count levels
                            (if total-duration-ms
                              (format "  total=%.2fms" (double total-duration-ms))
                              "")))))

    (str sb)))

(s/fdef format-text-report
  :args (s/cat :report ::specs/report)
  :ret string?
  :fn (fn [{ret :ret}] (str/starts-with? ret "=== Log Analysis Report ===")))

;;; --- CLI ---

(def cli-spec
  {:format {:desc "Output format: text, json" :default "text" :alias :f}
   :command {:desc "Command: analyze, count-by-level, top-errors, latency-percentiles, correlation-trace"
             :default "analyze" :alias :c}
   :after {:desc "Filter: only logs after this timestamp" :alias :a}
   :before {:desc "Filter: only logs before this timestamp" :alias :b}
   :correlation-id {:desc "Trace specific correlation/request ID" :alias :r}
   :top {:desc "Number of top errors to show" :default 10 :coerce :int :alias :n}
   :help {:desc "Show help" :alias :h :coerce :boolean}})

(defn read-lines [sources]
  (if (empty? sources)
    (line-seq (java.io.BufferedReader. *in*))
    (mapcat (fn [f]
              (when (fs/exists? f)
                (str/split-lines (slurp f))))
            sources)))

(s/fdef read-lines
  :args (s/cat :sources (s/coll-of string?))
  :ret (s/coll-of string?))

(defn analyze [entries {:keys [command correlation-id top]}]
  (case command
    "count-by-level" {:count-by-level (count-by-level entries)}
    "top-errors" {:top-errors (top-errors entries {:n top})}
    "latency-percentiles" {:latency (latency-percentiles entries)}
    "correlation-trace" (if correlation-id
                          {:correlation-trace (correlation-id-trace entries correlation-id)}
                          {:correlation-ids (group-by-correlation entries)})
    ;; default: full analysis
    {:total (count entries)
     :count-by-level (count-by-level entries)
     :top-errors (top-errors entries {:n top})
     :latency (latency-percentiles entries)
     :correlation-ids (group-by-correlation entries)}))

(s/fdef analyze
  :args (s/cat :entries ::specs/entries :opts ::specs/analyze-opts)
  :ret ::specs/analysis
  :fn (fn [{{:keys [entries opts]} :args ret :ret}]
        (if (#{"count-by-level" "top-errors" "latency-percentiles" "correlation-trace"}
             (:command opts))
          (= 1 (count ret))
          (= (count entries) (:total ret)))))

(defn -main [& args]
  (let [{:keys [opts args]} (cli/parse-args args {:spec cli-spec})
        {:keys [format command after before correlation-id top help]} opts]
    (when help
      (println "distributed-log-analyzer — Analyze logs from distributed systems")
      (println)
      (println "Usage: bb run [options] [files...]")
      (println "       cat logs.json | bb run [options]")
      (println)
      (println "Commands:")
      (println "  analyze              Full analysis report (default)")
      (println "  count-by-level       Count entries by log level")
      (println "  top-errors           Show top error messages")
      (println "  latency-percentiles  Compute latency statistics")
      (println "  correlation-trace    Trace entries by correlation ID")
      (println)
      (println (cli/format-opts {:spec cli-spec}))
      (System/exit 0))

    (let [lines (read-lines args)
          entries (->> lines
                       (map parse-line)
                       (filter some?)
                       vec)
          entries (if (or after before)
                    (filterv #(in-time-range? % {:after after :before before}) entries)
                    entries)
          result (analyze entries {:command command
                                   :correlation-id correlation-id
                                   :top top})]
      (case format
        "json" (println (json/generate-string result {:pretty true}))
        (if (contains? result :total)
          (print (format-text-report result))
          (println (json/generate-string result {:pretty true}))))

      (flush)
      (let [error-count (get-in result [:count-by-level "ERROR"] 0)]
        (System/exit (if (pos? error-count) 1 0))))))

(s/fdef -main
  :args (s/* string?))

(when (= *file* (System/getProperty "babashka.file"))
  (apply -main *command-line-args*))
