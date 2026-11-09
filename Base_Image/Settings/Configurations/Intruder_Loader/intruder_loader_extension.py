# intruder_loader_extension.py
#
# A Burp extension (Jython) that watches ONE shared queue folder - IntruderQueue/, a sibling of
# this tool's Projects/ folder, never inside any single project - and loads every request it
# finds there into Intruder via sendToIntruder(host, port, https, request).
#
# WHERE THE FILES COME FROM: the main app's "Push to Testing" button, next to the Threat-Model
# list in the request viewer. Each push writes one JSON file under:
#
#   IntruderQueue/<project name>/<WSTG-ID>__<random>.json
#
# A list of entries, each shaped like:
#   {
#     "host": "example.com", "port": 443, "https": true,
#     "raw_request_b64": "<base64 of the exact request bytes>",
#     "project": "...", "wstg_id": "WSTG-INJT-04", "xml_index": 1,
#     "method": "GET", "path": "/search?q=1", "best_match": "q"
#   }
#
# raw_request_b64 is base64, not plain text - some requests carry bodies or encodings that are
# not valid UTF-8, and base64 is the only way to carry arbitrary bytes through JSON without
# quietly corrupting them. Decode it, don't .encode() a text field.
#
# ---------------------------------------------------------------------------------------------
# ONE-TIME SETUP, done once in Burp's own UI (not something this app or this script can do for
# you - Burp does not expose any API that lets an outside process load an extension into it):
#
#   1. Settings > Extensions > Python Environment: set "Location of the Jython standalone JAR
#      file" to your Jython jar (only needed if Burp's BApp view shows a "Download Jython"
#      prompt next to Python extensions - if Python extensions already load fine, skip this).
#   2. Settings > Extensions > Installed: Add > Extension type: Python > select this file.
#   3. Settings > Extensions > Extensions: turn on "Automatically reload extensions on startup".
#
# After that, this extension reloads itself every time Burp starts - including a Burp you start
# from the command line (java -jar burpsuite...), which is what this project's "Intruder Loader"
# panel's Launch button actually runs. The panel cannot make Burp load the extension on its own;
# it only launches the Burp process, the same way starting Burp any other way would.
# ---------------------------------------------------------------------------------------------

import base64
import json
import os
import threading
import time

from burp import IBurpExtender

# Point this at the SAME folder the main app's INTRUDER_QUEUE_DIR resolves to. By default that is
# <this tool's own folder>/IntruderQueue - a sibling of Projects/, Base_Image/ and data/.
WATCH_FOLDER = "/path/to/red-team-audit-tool/IntruderQueue"
POLL_INTERVAL = 2  # seconds


class BurpExtender(IBurpExtender):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        callbacks.setExtensionName("Intruder Loader")

        t = threading.Thread(target=self.watchFolder)
        t.setDaemon(True)  # dies when Burp closes, same as any other background thread here
        t.start()

        callbacks.printOutput("[*] Intruder Loader watching: " + WATCH_FOLDER)

    def watchFolder(self):
        while True:
            try:
                self.scanOnce()
            except Exception as e:
                self._callbacks.printError("Watcher error: " + str(e))
            time.sleep(POLL_INTERVAL)

    def scanOnce(self):
        if not os.path.isdir(WATCH_FOLDER):
            return
        # One subfolder per project (never mixed - the main app guarantees this on write).
        for project_name in sorted(os.listdir(WATCH_FOLDER)):
            project_dir = os.path.join(WATCH_FOLDER, project_name)
            if not os.path.isdir(project_dir) or project_name == "processed":
                continue
            processed_dir = os.path.join(project_dir, "processed")
            for filename in sorted(os.listdir(project_dir)):
                if not filename.endswith(".json"):
                    continue
                filepath = os.path.join(project_dir, filename)
                if not os.path.isfile(filepath):
                    continue
                self.loadFile(filepath, processed_dir, filename)

    def loadFile(self, filepath, processed_dir, filename):
        try:
            with open(filepath, "r") as f:
                entries = json.load(f)
        except Exception as e:
            self._callbacks.printError("Could not read " + filepath + ": " + str(e))
            return  # leave it - a transient write-in-progress will parse fine next pass

        sent = 0
        for entry in entries:
            try:
                raw = base64.b64decode(entry["raw_request_b64"])
                self._callbacks.sendToIntruder(
                    str(entry["host"]),
                    int(entry["port"]),
                    bool(entry["https"]),
                    raw,
                )
                sent += 1
                self._callbacks.printOutput(
                    "[+] Sent to Intruder: " + str(entry.get("wstg_id", "?"))
                    + " " + str(entry.get("method", "")) + " " + str(entry.get("path", ""))
                    + " (" + str(entry["host"]) + ")"
                )
            except Exception as e:
                self._callbacks.printError("Skipped one entry in " + filepath + ": " + str(e))

        # Move the file out of the way once it's been handled, so a Burp restart never resends
        # it - an in-memory "already processed" set (the simplest version of this) forgets
        # everything the moment Burp closes.
        try:
            if not os.path.isdir(processed_dir):
                os.makedirs(processed_dir)
            os.rename(filepath, os.path.join(processed_dir, filename))
        except Exception as e:
            self._callbacks.printError("Sent " + str(sent) + " from " + filepath + " but could not move it to processed/: " + str(e))
