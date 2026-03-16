(ns distributed_log_analyzer.core
  (:require [babashka.cli :as cli]
            [babashka.fs :as fs]
            [clojure.string :as str]
            [cheshire.core :as json]))

(def cli-spec
  {:dir {:desc "Directory to scan" :default "." :alias :d}
   :format {:desc "Output format: text, json, edn" :default "text" :alias :f}
   :help {:desc "Show help" :alias :h :coerce :boolean}})

(defn -main [& args]
  (let [opts (cli/parse-opts args {:spec cli-spec})]
    (when (:help opts)
      (println "distributed-log-analyzer — Parse and analyze logs from distributed systems")
      (println)
      (println (cli/format-opts {:spec cli-spec}))
      (System/exit 0))
    ;; TODO: implement scanning logic
    (println (format "distributed-log-analyzer: scanning %s (format: %s)" (:dir opts) (:format opts)))
    (println "Not yet implemented — see CLAUDE.md for build order")))

(when (= *file* (System/getProperty "babashka.file"))
  (apply -main *command-line-args*))
