(ns distributed_log_analyzer.core-test
  (:require [clojure.test :refer [deftest is testing run-tests]]
            [distributed_log_analyzer.core :as core]
            [clojure.string :as str]))

(def sample-json-lines
  ["{\"timestamp\":\"2024-01-15T10:00:01Z\",\"level\":\"INFO\",\"message\":\"Server started\",\"request_id\":\"req-001\",\"duration_ms\":5}"
   "{\"timestamp\":\"2024-01-15T10:00:02Z\",\"level\":\"ERROR\",\"message\":\"Connection timeout\",\"request_id\":\"req-001\",\"duration_ms\":5000}"
   "{\"timestamp\":\"2024-01-15T10:00:03Z\",\"level\":\"ERROR\",\"message\":\"Connection timeout\",\"request_id\":\"req-002\",\"duration_ms\":5000}"
   "{\"timestamp\":\"2024-01-15T10:00:04Z\",\"level\":\"WARN\",\"message\":\"Retry attempt\",\"request_id\":\"req-001\",\"duration_ms\":200}"
   "{\"timestamp\":\"2024-01-15T10:00:05Z\",\"level\":\"DEBUG\",\"message\":\"Cache hit\",\"duration_ms\":2}"])

;;; --- Parsing Tests ---

(deftest test-parse-json-line
  (testing "parses JSON log line"
    (let [entry (core/parse-line (first sample-json-lines))]
      (is (= :json (:format entry)))
      (is (= "INFO" (:level entry)))
      (is (= "Server started" (:message entry)))
      (is (= "req-001" (:request-id entry)))
      (is (= 5 (:duration-ms entry))))))

(deftest test-parse-json-alternate-fields
  (testing "parses JSON with alternate field names"
    (let [entry (core/parse-line "{\"time\":\"2024-01-15T10:00:01Z\",\"severity\":\"warn\",\"msg\":\"slow\",\"trace_id\":\"t-1\",\"latency_ms\":300}")]
      (is (= :json (:format entry)))
      (is (= "WARN" (:level entry)))
      (is (= "slow" (:message entry)))
      (is (= "t-1" (:request-id entry)))
      (is (= 300 (:duration-ms entry))))))

(deftest test-parse-syslog-line
  (testing "parses syslog line with level"
    (let [entry (core/parse-line "Jan 15 10:00:01 web01 nginx[1234]: ERROR Request failed request_id:req-100")]
      (is (= :syslog (:format entry)))
      (is (= "ERROR" (:level entry)))
      (is (= "web01" (:host entry)))
      (is (= "nginx" (:service entry)))
      (is (= "1234" (:pid entry)))
      (is (= "req-100" (:request-id entry))))))

(deftest test-parse-syslog-no-level
  (testing "syslog without explicit level defaults to INFO"
    (let [entry (core/parse-line "Jan 15 10:00:06 db01 postgres[9012]: Vacuum completed")]
      (is (= :syslog (:format entry)))
      (is (= "INFO" (:level entry)))
      (is (= "Vacuum completed" (:message entry))))))

(deftest test-parse-syslog-duration
  (testing "parses duration from syslog message"
    (let [entry (core/parse-line "Jan 15 10:00:03 db01 postgres[9012]: WARN Slow query detected duration:2500ms request_id:req-101")]
      (is (== 2500.0 (:duration-ms entry)))
      (is (= "req-101" (:request-id entry))))))

(deftest test-parse-access-log
  (testing "parses access log line"
    (let [entry (core/parse-line "192.168.1.1 - - [15/Jan/2024:10:00:01 +0000] \"GET /api/users HTTP/1.1\" 200 1234 0.050")]
      (is (= :access-log (:format entry)))
      (is (= "INFO" (:level entry)))
      (is (= "GET /api/users 200" (:message entry)))
      (is (= 200 (:status entry)))
      (is (== 50.0 (:duration-ms entry))))))

(deftest test-parse-access-log-error
  (testing "access log 500 maps to ERROR level"
    (let [entry (core/parse-line "192.168.1.1 - - [15/Jan/2024:10:00:03 +0000] \"GET /api/orders HTTP/1.1\" 500 256 2.500")]
      (is (= "ERROR" (:level entry)))
      (is (= 500 (:status entry)))
      (is (== 2500.0 (:duration-ms entry))))))

(deftest test-parse-access-log-warn
  (testing "access log 4xx maps to WARN level"
    (let [entry (core/parse-line "192.168.1.2 - - [15/Jan/2024:10:00:02 +0000] \"POST /api/login HTTP/1.1\" 401 89 0.120")]
      (is (= "WARN" (:level entry)))
      (is (= 401 (:status entry))))))

(deftest test-parse-blank-lines
  (testing "blank lines return nil"
    (is (nil? (core/parse-line "")))
    (is (nil? (core/parse-line "   ")))))

;;; --- Analysis Tests ---

(deftest test-count-by-level
  (testing "counts entries by level"
    (let [entries (mapv core/parse-line sample-json-lines)
          counts (core/count-by-level entries)]
      (is (= 1 (get counts "INFO")))
      (is (= 2 (get counts "ERROR")))
      (is (= 1 (get counts "WARN")))
      (is (= 1 (get counts "DEBUG"))))))

(deftest test-top-errors
  (testing "returns top errors grouped by message"
    (let [entries (mapv core/parse-line sample-json-lines)
          errors (core/top-errors entries)]
      (is (= 1 (count errors)))
      (is (= "Connection timeout" (:message (first errors))))
      (is (= 2 (:count (first errors)))))))

(deftest test-top-errors-limit
  (testing "respects :n limit"
    (let [entries (mapv core/parse-line
                        ["{\"level\":\"ERROR\",\"message\":\"err-a\"}"
                         "{\"level\":\"ERROR\",\"message\":\"err-a\"}"
                         "{\"level\":\"ERROR\",\"message\":\"err-b\"}"
                         "{\"level\":\"ERROR\",\"message\":\"err-c\"}"])
          errors (core/top-errors entries {:n 2})]
      (is (= 2 (count errors)))
      (is (= "err-a" (:message (first errors)))))))

(deftest test-latency-percentiles
  (testing "computes latency percentiles"
    (let [entries (mapv core/parse-line sample-json-lines)
          stats (core/latency-percentiles entries)]
      (is (= 5 (:count stats)))
      (is (== 2 (:min stats)))
      (is (== 5000 (:max stats)))
      (is (pos? (:avg stats)))
      (is (some? (:p50 stats)))
      (is (some? (:p95 stats))))))

(deftest test-latency-percentiles-empty
  (testing "handles entries with no duration"
    (let [entries (mapv core/parse-line ["{\"level\":\"INFO\",\"message\":\"no duration\"}"])
          stats (core/latency-percentiles entries)]
      (is (= 0 (:count stats))))))

(deftest test-correlation-id-trace
  (testing "traces entries by correlation ID"
    (let [entries (mapv core/parse-line sample-json-lines)
          traced (core/correlation-id-trace entries "req-001")]
      (is (= 3 (count traced)))
      (is (every? #(= "req-001" (:request-id %)) traced)))))

(deftest test-correlation-id-trace-not-found
  (testing "returns empty for unknown correlation ID"
    (let [entries (mapv core/parse-line sample-json-lines)
          traced (core/correlation-id-trace entries "nonexistent")]
      (is (empty? traced)))))

(deftest test-group-by-correlation
  (testing "groups entries by correlation ID"
    (let [entries (mapv core/parse-line sample-json-lines)
          groups (core/group-by-correlation entries)]
      (is (= 2 (count groups)))
      (is (= "req-001" (:request-id (first groups))))
      (is (= 3 (:count (first groups)))))))

;;; --- Time Filtering ---

(deftest test-time-range-filter-after
  (testing "filters entries after timestamp"
    (let [entries (mapv core/parse-line sample-json-lines)
          filtered (filterv #(core/in-time-range? % {:after "2024-01-15T10:00:03Z"}) entries)]
      (is (= 3 (count filtered))))))

(deftest test-time-range-filter-before
  (testing "filters entries before timestamp"
    (let [entries (mapv core/parse-line sample-json-lines)
          filtered (filterv #(core/in-time-range? % {:before "2024-01-15T10:00:02Z"}) entries)]
      (is (= 2 (count filtered))))))

(deftest test-time-range-filter-both
  (testing "filters entries in time range"
    (let [entries (mapv core/parse-line sample-json-lines)
          filtered (filterv #(core/in-time-range? % {:after "2024-01-15T10:00:02Z"
                                                     :before "2024-01-15T10:00:04Z"}) entries)]
      (is (= 3 (count filtered))))))

;;; --- File Reading ---

(deftest test-read-from-file
  (testing "reads log lines from file"
    (let [lines (core/read-lines ["test-resources/json.log"])
          entries (->> lines (map core/parse-line) (filter some?) vec)]
      (is (= 10 (count entries)))
      (is (every? #(= :json (:format %)) entries)))))

(deftest test-read-from-multiple-files
  (testing "reads from multiple files"
    (let [lines (core/read-lines ["test-resources/json.log" "test-resources/access.log"])
          entries (->> lines (map core/parse-line) (filter some?) vec)]
      (is (= 18 (count entries))))))

;;; --- Full Analysis ---

(deftest test-analyze-full
  (testing "full analysis produces all sections"
    (let [entries (mapv core/parse-line sample-json-lines)
          result (core/analyze entries {:command "analyze" :top 10})]
      (is (contains? result :total))
      (is (contains? result :count-by-level))
      (is (contains? result :top-errors))
      (is (contains? result :latency))
      (is (contains? result :correlation-ids)))))

(deftest test-analyze-subcommands
  (testing "subcommands return focused results"
    (let [entries (mapv core/parse-line sample-json-lines)]
      (is (contains? (core/analyze entries {:command "count-by-level"}) :count-by-level))
      (is (contains? (core/analyze entries {:command "top-errors" :top 5}) :top-errors))
      (is (contains? (core/analyze entries {:command "latency-percentiles"}) :latency))
      (is (contains? (core/analyze entries {:command "correlation-trace" :correlation-id "req-001"})
                     :correlation-trace)))))

;;; --- Mixed Format ---

(deftest test-mixed-formats
  (testing "parses mixed log formats from file"
    (let [lines (core/read-lines ["test-resources/mixed.log"])
          entries (->> lines (map core/parse-line) (filter some?) vec)
          formats (set (map :format entries))]
      (is (contains? formats :json))
      (is (contains? formats :syslog))
      (is (contains? formats :access-log)))))

(when (= *file* (System/getProperty "babashka.file"))
  (let [{:keys [fail error]} (run-tests)]
    (System/exit (if (pos? (+ fail error)) 1 0))))
