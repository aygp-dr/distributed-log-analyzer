(ns distributed_log_analyzer.specs-test
  "Generative checks for every pure s/fdef'd fn, plus data-spec sanity.
  Per https://clojure.org/guides/spec (Testing)."
  (:require [clojure.spec.alpha :as s]
            [clojure.spec.test.alpha :as stest]
            [clojure.test :refer [deftest is testing]]
            [distributed_log_analyzer.core :as core]
            [distributed_log_analyzer.specs :as specs]))

(def ^:private check-opts {:clojure.spec.test.check/opts {:num-tests 50}})

;; Side-effecting fns: fdef'd for instrumentation, never generatively checked.
;; read-lines reads files or stdin; -main prints and exits.
(def ^:private side-effecting
  #{`core/read-lines `core/-main})

(defn- checkable []
  (remove side-effecting (stest/enumerate-namespace 'distributed_log_analyzer.core)))

(deftest fdefs-hold-under-generative-testing
  (let [results (stest/check (checkable) check-opts)]
    (is (seq results) "expected at least one fdef'd fn to check")
    (doseq [r results]
      (testing (str (:sym r))
        (is (nil? (:failure r))
            (pr-str (stest/abbrev-result r)))))))

(deftest data-specs-generate-and-conform
  (doseq [k [::specs/line-text ::specs/entry ::specs/entries ::specs/latency
             ::specs/report ::specs/time-window ::specs/analyze-opts]]
    (testing (str k)
      (is (every? (fn [[v _]] (s/valid? k v)) (s/exercise k 10))))))

(deftest real-values-conform
  (let [lines (core/read-lines ["test-resources/json.log" "test-resources/syslog.log"
                                "test-resources/access.log" "test-resources/mixed.log"])
        entries (->> lines (map core/parse-line) (filter some?) vec)]
    (testing "entries parsed from test-resources/*.log"
      (is (s/valid? (s/coll-of ::specs/line-text) lines))
      (is (s/valid? ::specs/entries entries)))
    (testing "the full analysis of those entries"
      (let [report (core/analyze entries {:command "analyze" :top 10})]
        (is (s/valid? ::specs/report report))
        (is (string? (core/format-text-report report)))))))
