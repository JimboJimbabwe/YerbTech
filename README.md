# Red Team Audit Tool

A local Node.js app that acts as a project manager and WSTG checklist for pen-test engagements.

## Run it

```
npm install
npm start          # http://127.0.0.1:3000
npm test           # tests against throwaway folders
```

Before the first run, put these in place:

| What | Where |
|---|---|
| Your `wstg_io_config.json`, **renamed** `wstg_io.json` | `data/json/wstg_io.json` |
| Your `wstg_reporting.json` | `data/json/wstg_reporting.json` |
| Your template folder `WSTG_Repository` | `Base_Image/WSTG_Repository` |

The server prints what it found on startup. Both JSON files are re-read when they change, so you can edit them while it runs.

Settings (environment variables): `PORT`, `HOST`, `PROJECTS_DIR`, `BASE_IMAGE_DIR`, `DATA_DIR`, `MAX_COPY_BYTES`, `MAX_XML_BYTES` (default 1 GiB), `ALLOWED_HOSTS`.
It binds to `127.0.0.1` on purpose. It reads and writes engagement data, so don't expose it on a network without thinking about it.

## Pages

1. `/` Project folders from `/Projects` plus an **Add project** button. Adding copies `Base_Image/WSTG_Repository` to `Projects/<Name>/WSTG_Repository`.
2. `/project/<name>` Pre-flight briefing: are the folders and both JSON files in order? Then **Open workspace**.
3. `/project/<name>/workspace` Checklist on the right, what/why panel to its left, open space reserved on the far left.
4. `/project/<name>/questionnaires` Answer the WSTG items that are mostly questions (see below), reached from a pill in the workspace header.

## The diagnostic lights

Click an assessment to open its box. Each of Scripts, JSON, XML and Wordlists gets a light, based on the **input** requirements in `wstg_io.json`:

| Light | Meaning |
|---|---|
| Green | Every required input is present |
| Amber | Present, but filed in a different sub-folder than expected |
| Red | At least one required input is missing |
| Grey | Nothing required, or the assessment has no entry in `wstg_io.json` |

Where files are expected is one table at the top of `lib/resources.js`. Change a path there and everything follows.
Outputs (`*_out`, sitreps) never turn a light red, because they don't exist before you run the scripts. They're listed under "Files this assessment produces".

## Decisions I made that you may want to change

- **Operator-supplied inputs.** Titles like "Item-specific artifact" have no fixed name. They count as present when the folder holds at least one file that no named requirement accounts for.
- **Names built at run time** (`curl_<ts>.md`, `EP_0.txt...EP_4.txt`) can't be checked, so they're informational only.
- **Script annotations are stripped**: `"info10_collect.py (Script 1 of 2)"` is checked as `info10_collect.py`. By extension: `.py` in `python`, `.js` in `JS`, `.go` in `GO`, `.sh` in `Kali_Tools`.
- **Sitreps** are extracted from the free-text `sitrep_or_output_files` strings on a best-effort basis and checked in `Inputs/Data`.
- Lookups are case-insensitive, and `Wordlist`/`Wordlists` both work.
- Test folders are found by name (`WSTG-INFO-01`, optionally followed by `_description`), so both of your naming styles resolve.
- Wordlist copy is capped at 5 MB (`MAX_COPY_BYTES`) and refuses binary files. Symlinked wordlists are fine.

## Things in your data worth knowing about

- **Directory-style XML inputs.** ATHN-10 (`weak_channels.xml`) and ATHZ-02 (`peruser_walk.xml`) actually take a *folder* of captures. They'll show red unless a file with that exact name exists.
- **JSON living in `Inputs/Data`.** Your notes say CONF-12's `CSP_Strings.json` and ATHN-08's `optionals_keywords.json` are confirmed present in `Inputs/Data`. The lights treat that as amber ("found in Inputs/Data"), not red.
- **Entries not tied to one assessment.** `WSTG-INJT (distributor)` and `WSTG-CLNT (unfinished generic pipeline)` can't be mapped to a folder. They're listed on the pre-flight page and skipped.
- **Assessments with no `wstg_io.json` entry** (for example INFO-06, 07, 09) stay grey.
- The `first/` folder in your tree is ignored. Only `WSTG_Repository` is copied.

## Burp Proxy XML (sidebar + request viewer)

The burger button (top left of the workspace) opens a sidebar. **Add XML files** expands into four square drop zones (Raw, Authorization, Authentication, Input surface): click one or drop a file on it. Nmap Output XML and Intruder XML are greyed copies, with no logic yet.

**Where things go** (per project):

```
project_utilities/files/XML/burp_proxy/<raw|authorization|authentication|input_surface>/<category>.xml   the one stored copy
project_utilities/archive/XML/burp_proxy/<category>/<timestamp>_<category>.xml                            replaced uploads
project_utilities/manifest.json                                                                           what was copied where
<assessment>/Inputs/XML/<name from wstg_io.json>                                                          the distributed copies
```

- The stored file is always named `raw.xml`, `authorization.xml`, `authentication.xml` or `input_surface.xml`. It is copied into each assessment it feeds, renamed to that assessment's `xml_in` title (`raw.xml` becomes `fingerprint_targets.xml`).
- **Routing** is `data/json/xml_routing.json` (a draft schema, replace it with yours; the `_meta` block explains each field). Defaults: Raw = INFO (not INFO-07) + CONF; Authorization = INJT, ERRH, BUSL, ATHZ; Authentication = IDNT, ATHN, SESS, INJT, CRYP; Input surface = CLNT. APIT and WASM are left out.
- An assessment only receives a file if `wstg_io.json` lists an `xml_in` title for it **whose `type` is `burp_proxy_xml` or `burp_session_walk_xml`**. Entries with no type are skipped and listed under "Where the files went" (set `include_untyped` to change that).
- **INJT is fed by two categories**, so both copies are kept as `<name>__authorization.xml` and `<name>__authentication.xml`, and the viewer shows a toggle. The XML light treats either as present ("datasets: ...").
- **Re-uploading** replaces the stored file and archives the old one. Files dropped by hand into the intake folders are noticed the next time the sidebar or viewer loads.
- Uploads stream to disk (never into memory), are capped by `MAX_XML_BYTES`, and must contain the `<items>` root element. A 176 MB / 20,000-request export uploads in about 2.5 s and indexes in about 4 s.
- **Viewer**: request side only. The request is the large box on top, the list of requests (filterable, loads as you scroll) sits underneath. Click a row, or use the arrow keys. Request data is shown as plain text only. A request longer than 1 MB is cut for display and flagged.

## Run order and commands

Open an assessment in the checklist and expand **Run order and commands**. Each script from `data/json/wstg_tools_procedures.json` is listed in run order with **Copy** (the default command) and **Build...** (a dialog for optional flags, presets and the shell). **Copy all in order** copies every script's command, one per step. Nothing is ever executed: it only builds text.

- **Shell toggle** (PowerShell or bash) changes quoting and `python` versus `python3`. The choice is remembered in the browser; the first visit defaults to PowerShell on a Windows server and bash elsewhere. "Start in the assessment folder first" adds a `Set-Location` or `cd`.
- **Paths are absolute**, built from the project folder and the assessment ID. A file input's location comes from its tag: `XML_INPUT` is `Inputs/XML`, `JSON_INPUT` is `Inputs/JSON`, `WORDLIST_INPUT` is `Inputs/Wordlists`. The file name comes from `wstg_io.json`, so an XML input resolves to the Burp copy that was distributed there. If an assessment has two Burp datasets (INJT), both are offered in a drop-down. The path strings inside the procedures file are only used as hints, because they use several different styles.
- **Chains**: a later script's input is matched to an earlier script's output in the same assessment (for example `--url-list` to `curl_urls.txt`). It shows "not there yet; created by <script>" rather than "missing".
- **Optional flags** start unchecked, so a default copy is the shortest valid command. Required values that can't be resolved show as a quoted `<placeholder>` and the Copy button says how many are left.
- **Presets** come from alternative invocations written in the file (`|` alternatives and `run_variants`). They only switch flags on or off.
- **Safety**: typed values are quoted for the chosen shell and line breaks are replaced with spaces, so a value can't smuggle in a second command.
- **`takes_value`**: the file doesn't say whether a flag takes a value, so `node tools/annotate_procedures.js` adds `takes_value` (and `flag_required` for output flags) to the JSON. Run it without `--write` to preview. It never overwrites a field you've set by hand, so correct any wrong ones in the file. Flags it can't classify are listed, and the builder treats them as "value optional" (leave the box empty to pass just the flag). Run it again after you merge in new categories.
- Assessments with no entry in the procedures file say so. INJT, CLNT, ERRH, APIT and WASM show this until their modules are added.
- Scripts with no documented command line (`command: null`) list their documented inputs only and say "flags not documented".

## Left for later

- **Redaction** of sensitive Burp data (you said it's coming). Stored and copied files are currently unmodified exports.
- Response side of the viewer; Nmap and Intruder logic.
- Running the scripts from the GUI (this feature only builds the commands).

- **Anti project spoofing.** Not implemented, as requested. Comments marking where it goes are in `lib/projects.js` (`listProjects`) and `public/js/home.js`.
  Separately, project names are sanitized for path safety only (no `../`, no Windows device names). That's not the spoofing check.
- Results of earlier checks aren't saved anywhere yet. Lights are computed live from the file system.

## Settings folder

Every new project gets `Settings/Configurations/` next to `WSTG_Repository/`:

```
Settings/Configurations/
  Mouse_Tool/   python/  javascript/  mouse_tool.json
  Utilities/    JSON/injection_router.json
  Wordlists/    (three JSON files)
```

- The **folders** are always created from a list in `lib/settings.js`. The **files** are never written by the tool; they are copied (never overwriting) from an optional `Base_Image/Settings` template, so you supply `mouse_tool.json` and `injection_router.json` yourself.
- Older projects get the folders (and any template files) the first time their briefing page is opened. The briefing shows a "Settings" check listing any expected file that is still missing.
- `settingsRoot()` is the single place that decides where Settings lives. A global location can replace the per-project one later by changing that one function.

### Mouse_Tool paths

`Base_Image/Settings/Configurations/Mouse_Tool/mouse_tool.json` ships as the template (copied into each new project, never overwritten). It holds the six client-side targets (CLNT-01..03, INJT-01, 02, 08), keyed by WSTG ID, with `Input_Folder`, `Output_Folder` and `XML_Path` relative to the project's `WSTG_Repository`.

- `GET /api/projects/:name/mouse` lists the targets; `GET /api/projects/:name/mouse/:wstgId` returns the absolute folders. Read-only; absolute paths, `..` escapes and unknown IDs are refused.
- Each target also has `Master_Folder` (`…/Outputs/test_outputs`); the response adds `Master_File` (`<WSTG-ID>_association.json` in it) and `Xml` (the single `.xml` in `XML_Path`, or an error if there are none or several).
- `GET`/`PUT /api/projects/:name/mouse/active` read and write `Settings/Configurations/Mouse_Tool/active_target.json` (`{"wstg_id": "..."}`), the one file in Settings this tool writes (state, not config; atomic write). The Mouse_Tool script polls it.
- The Python and JS scripts are not changed yet.


## Injection test-data pipeline (script 1 / 2 / 3 + orchestrator)

Three scripts, templated into `Base_Image/Settings/Configurations/Utilities/python/` and
copied into each project (never overwritten) next to the Mouse_Tool scripts:

- **`shuttle_gen.py`** (script 1) — turns a captured hover-trace item (`element` + `domAttributes`)
  into a cross-product of DOM-access "shuttles" and XSS context strings, deduplicates the result,
  then keeps a random `--cap-percent` (default 10%) slice of what's left. The sample is **not**
  seeded: the same input gives a different slice on every run, by design. The volume cap is
  deliberate; the cross-product itself (which shuttle/context combos get generated) is left as-is.
- **`rebuild_tag.py`** (script 2) — rebuilds the HTML tag from the same item and splits it in two
  around one operator-supplied string, so a payload can be slotted in exactly where that string
  was. A `--split` value not found in any attribute fails cleanly (exit 1, one-line message), not
  with a traceback — the orchestrator relies on that to skip a job without crashing.
- **`tag_combine.py`** (script 3) — pairs one of script 1's wordlists with one of script 2's splits
  for the *same* source file and writes `tag_start + payload + tag_end`, one combined line per
  surviving payload. It only ever combines the two files it's given; the rule that an Input
  wordlist must pair with that same file's Input split (never an Output's) is enforced by the
  orchestrator, which is the only thing that chooses which files to hand it. See the `# TODO(pairing)`
  note at the top of the file.
- **`orchestrator.py`** — reads `injection_router.json` for the WSTG IDs on one side (`Client_Side`
  by default), resolves each one's folders from `mouse_tool.json` (same relative-path safety rule
  as the Node side's `lib/mouse.js`), and for every `Associations[]` entry's `Input`/`Output` file
  runs script 1 across every item, then script 2 across every item, then script 3 — three full
  passes, not interleaved, matching how the operator wants to watch it run. Every subprocess call
  is an explicit argument list; nothing goes through a shell. Output lands in that WSTG item's
  `Outputs/test_outputs` folder:

  ```
  {xml_index}_wordlist_SFCi{N}.txt / SFCo{N}.txt    (script 1)
  {xml_index}_tagsplit_SFCi{N}.json / SFCo{N}.json  (script 2)
  {xml_index}_tagged_SFCi{N}.txt / SFCo{N}.txt       (script 3 — the deliverable)
  ```

  Run it directly, e.g.:
  ```
  python3 orchestrator.py --project-root /path/to/Projects/MyProject --split "rested"
  ```
  (`--scripts-dir`, `--router`, `--mouse-config` and `--cap-percent` all have project-relative
  defaults and only need overriding for testing.) The GUI's Mouse Tool panel runs this for you
  (see below) and always runs it against `Client_Side` - this pipeline needs mouse-captured
  Input/Output association data, which only exists for the client-side (DOM-interception) items.


## Server-side wordlist pipeline

A separate, smaller script - `server_side_orchestrator.py` (renamed from the operator's own
`wstg_wordlist.py`), templated alongside the rest of `Utilities/python/` - for the server-side
WSTG items. No mouse capture involved: base attack commands get WAF-evasion strings inserted
into them and the result is one wordlist per item.

Three more read-only template files (templated like `injection_router.json`, never written by
this tool) drive it, all joined by WSTG ID:

- **`injection_router.json`**'s `Server_Side` list — which items to generate for, and each
  item's own category folder. (The category is no longer hardcoded to `07_Injection` the way
  the original script had it - that was a real bug, since not every server-side item lives
  there.)
- **`server_side_waf_map.json`** (new) — the routing key: which `waf_items.json` category each
  WSTG ID's commands get smuggled with. Keyed to match `injection_router.json`'s spelling of
  each ID, since that file is the authority on category/folder.
- **`server_side_inj.json`** — the base attack commands per WSTG ID (hand-written, not generated
  here).
- **`waf_items.json`** — the WAF-evasion string libraries, by category.

An item only gets a wordlist when its ID appears in **all three** files. When it doesn't, the
script prints a one-line skip reason and moves on - it never crashes. This project's own two
supplied data files actually disagree on the SSRF item's ID right now: `injection_router.json`
spells it `WSTG-INJT-19`, `server_side_inj.json` spells it `WSTG-INPV-19`. Until one of them is
corrected to match the other, SSRF will show up as skipped (`not in server_side_inj.json`) -
that's the mismatch being caught and reported, not a bug in the join logic.

For each matched item, every base command is combined with 3 WAF strings from its routed
category (`--waf-per-cat`), inserted at up to 3 random valid positions each (`--max-pos-pairs`),
deduplicated, and capped at 800 lines total (`--max-lines`, base commands always kept first).
Output: `Outputs/test_outputs/<wstg_id>_WL.txt`.

```
python3 server_side_orchestrator.py --project-root /path/to/Projects/MyProject
```

A standalone `--test-full-run` mode (uncapped, dumps into the working directory or
`--test-full-run-dir`) is kept from the original script for quick manual checks outside any
project.


## Mouse Tool panel (GUI)

A "Mouse Tool" toggle in the workspace header opens a panel (same style as the XML sidebar) with:

- **Active WSTG item** - a dropdown over the items in `mouse_tool.json`; picking one calls
  `PUT /mouse/active`.
- **Clipboard interceptor** - Start/Stop buttons around `clipboard_interceptor.py`
  (`POST /mouse/listener/start` / `/stop`, `GET /mouse/listener/status`, polled every 4s while
  the panel is open). This needs the operator's own desktop (global hotkeys, clipboard), so it
  only makes sense when the browser and the server share a machine - this tool's usual setup.
  The server tracks the process in memory only; a server restart forgets it was running, same
  as any other local dev tool.
- **Injection test-data pipeline (client-side)** - a split-string field, a cap-percent field and
  a "Generate test data" button that calls `POST /mouse/orchestrator/run`, waits for the full
  three-phase run, and shows its log.
- **Server-side wordlist pipeline** - a single "Generate server-side wordlists" button that
  calls `POST /mouse/server-side/run` and shows its log (including any skipped-item lines).

`clipboard_interceptor.py` (renamed from `clipboard_listener.py`) now has two modes. With
`--config <mouse_tool.json> --project-root <project>` it resolves every input/output/XML/master
folder from the project's own `mouse_tool.json`, polls `active_target.json` so the page and the
`F6`/`F7` hotkeys agree on which item is active, keeps each item's turn counter independent, and
rejects a clipboard JSON tagged for a different item (`mouse_target.wstg_id`) with an ALERT
instead of saving it under the wrong one. Without `--config` it behaves exactly as the original
script did (`--category`/`--input_json`/`--output_json`/`--xml`/`--master`), so nothing already
built on the old flags breaks. `--max` now defaults to no limit (was 10).

`listener.js` (renamed from the hover-trace script) no longer carries `BASE_PATH` or
`CATEGORY_DESCRIPTIONS`; it only tags its output with `mouse_target.wstg_id`, which the Python
substitutes for the active item when it copies the file to the clipboard.


## Reporting tool (screenshot overlay)

A "Reporting" toggle in the workspace header opens a panel to start/stop a desktop overlay that
walks you through WSTG category -> item -> a capture rectangle -> a typed description, and
writes everything out as it goes. Like Mouse Tool, this needs the operator's own desktop (a
real mouse, a real display) so it only makes sense when the browser and the server share a
machine.

**Interaction (all on the live desktop, not in the browser):**

- **Middle-click** opens a row of category circles across the top of the screen; scroll or hover
  moves the highlight; middle-click again confirms and opens the chosen category's items the
  same way; middle-click a third time confirms the item - you're now "primed."
- **Space** shows a capture rectangle that follows the cursor - this rectangle *is* the capture
  frame, so F9 refuses to fire until one is shown.
- **Shift** (left or right) picks which axis - length or height - the next **scroll** resizes.
- **F9** takes the screenshot (hiding the overlay first so it never captures itself), then opens
  a small window to type a description; **Ctrl+Enter** or the Save button writes the step,
  **Esc** cancels the window without saving.
- **Esc** (outside the description window) un-primes - drops the locked category/item and hides
  the rectangle - so middle-click starts a fresh pick.
- **Ctrl+Alt+Q** quits the overlay from anywhere.

None of this suppresses any OS default: middle-click, scroll and the keys above have nothing
competing for them, so every piece works by *globally observing* input (`pynput`'s listeners),
never by grabbing or blocking it - the one genuinely hard approach (suppressing the system's own
right-click menu) was dropped from the design for exactly this reason.

**Where it writes:**

- Each screenshot lands in that WSTG item's own `Reporting/` folder (a sibling of `Inputs/`,
  `Outputs/`, etc.), created on first capture - never from the project template, same as
  `Outputs/test_outputs/` in Findings Entry.
- Every step's description, step number and image path are also written to one consolidated
  `<project>/Reporting/reporting_index.json` at the project root (also created lazily), so
  there's a single file to read when building a final report - shape is
  `{ category: { wstg_id: { name, steps: [{ step, description, image_path }] } } }`, with
  `image_path` relative to the project root.

**GUI side:** `GET /reporting/summary` (category/item/step counts from `reporting_index.json`),
`GET /reporting/overlay/status`, `POST /reporting/overlay/start` / `/stop` - all in
`lib/reporting.js` / `lib/reportingProc.js`, same shape as `lib/mouse.js` / `lib/mouseProc.js`.
Starting the overlay spawns `tools/reporting/reporting_overlay.py --project-root <project> --reporting-file <wstg_reporting.json>` - the same `wstg_reporting.json` the server itself reads
(`lib/data.js`'s `getReporting()`), so the overlay's categories/items can never drift from the
checklist the rest of the app shows.

**Dependencies on the machine running the overlay** (the Kali box, in the usual setup): `pip
install pynput`, `python3-tk` (Tk is not always in the default `python3` package), and `scrot`
for screenshots (falls back to `pip install pillow`'s `ImageGrab` if `scrot` isn't found).

**Standalone demo:** `tools/reporting/mouse_reporter_demo.py` is the same interaction model
against a small hardcoded sample WSTG list, no project needed, no real screenshot taken (it logs
what it would have captured) - useful for trying the controls before wiring it into a project.


## Error Handling wordlists (WSTG-ERRH-01 / WSTG-ERRH-02)

`tools/errh/unicode.json` - 240 unusual Unicode characters across 16 categories (control
characters, invisible/bidi-override characters, homoglyphs, astral-plane oddities, etc.) - plus
two standalone scripts, `errh01_wordlist.py` and `errh02_wordlist.py`, one per item. Place
`unicode.json` in either item's `Inputs/JSON/` (both scripts check their own folder, then the
other item's, before giving up - no need to duplicate it, though you can).

The two scripts are meant to be run as a pair and deliberately coordinate so you get two
*non-overlapping* wordlists instead of two copies of the same thing:

- If an item already has a wordlist (`Outputs/test_outputs/<wstg_id>_WL.txt`), running its script
  again does nothing (`--force` to rebuild anyway).
- Otherwise it checks whether its sibling already has one. If so, it reads it and omits every
  character already there before picking. If not, it just picks normally - a random,
  category-distributed selection (roughly even picks per category, not a straight
  `random.sample()` that a large category could dominate).
- Run them in either order - whichever goes first just picks normally, and the other adapts.

Characters that would break a one-value-per-line text file if written raw (LF, CR, and the rest
of the C0 control range, NEL/LS/PS - several of which are legitimately in `unicode.json`'s own
"C0 Control Characters" and "Invisible & Directional Characters" categories, since that's the
whole point of testing with them) are backslash-escaped on the line (`\x00`, `\n`, ` `, ...);
everything else is written as the literal character.

```
python3 tools/errh/errh01_wordlist.py --project-root /path/to/Projects/MyProject
python3 tools/errh/errh02_wordlist.py --project-root /path/to/Projects/MyProject
```

Both resolve their own and each other's folder by scanning the project tree for the WSTG ID
itself (same approach as `find_wstg_folder` elsewhere in this project) - never a hardcoded
category path, so it doesn't matter what the actual `NN_Error_Handling`-style folder is named.

**GUI side:** once a script is in that item's own `Utilities/python/`, expanding WSTG-ERRH-01 or
WSTG-ERRH-02's diagnostic-lights box (the same card the "Re-check" button lives on) shows a
"Generate wordlist" button for that item only - ERRH-01's box never offers to run ERRH-02's
script or vice versa, same as the scripts themselves never look past their one sibling.
`POST /tests/:id/errh-wordlist` (`lib/errh.js`) runs it to completion (like the server-side
wordlist pipeline - no process to track) and the box refreshes afterward, so the new file shows
up in the wordlists light and the "files this assessment produces" list without an extra click.

## Insecure Deserialization (WSTG-INJT-23): ysoserial / phpggc wrapper

**Heads up on the WSTG ID:** `tools/deser/deser_wordlist.py` and its GUI section are keyed to
**WSTG-INJT-23**. An older doc in this project (`07_Injection/inj_distributor.py`) lists Insecure
Deserialization as WSTG-INJT-21, but that's a stale numbering - `wstg_reporting.json`, which is
what actually drives the checklist sidebar, has WSTG-INJT-21 as CSV Injection and WSTG-INJT-23 as
Insecure Deserialization (CSV Injection and Prototype Pollution were inserted ahead of it at some
point). If your own project tree still has the item folder named `WSTG-INJT-21` for this test,
rename it to `WSTG-INJT-23` first, or this tool won't find it.

`tools/deser/deser_wordlist.py` wraps two external tools - **ysoserial** for Java gadget chains and
**phpggc** for PHP gadget chains - behind one script and one GUI card, picked with `--language`.
**Neither tool ships with this app** - they're expected to already be on the box (Kali packages
`ysoserial`; `phpggc` is normally cloned from https://github.com/ambionics/phpggc). This script was
written and exercised against documented CLI behavior for both, with the gadget-discovery,
cross-product, skip-on-failure, raw-save and encode steps all verified end to end against stand-in
scripts standing in for the real binaries - but not against the real `ysoserial`/`phpggc`
themselves, since neither is installed in the environment this was built in. Smoke-test it once
against your own install before relying on it.

```
python3 tools/deser/deser_wordlist.py --project-root /path/to/Projects/MyProject \
    --language java --sys-type linux
python3 tools/deser/deser_wordlist.py --project-root ... --language php --sys-type windows --command id
python3 tools/deser/deser_wordlist.py --project-root ... --language java --sys-type linux --gadget CommonsCollections6
```

Flags:

- `--language` (`php` | `java`, required) - which underlying tool runs.
- `--sys-type` (`linux` | `windows`, required) - which command-list file this run reads by
  default: `Inputs/Data/linux.txt` or `Inputs/Data/windows.txt`, inside WSTG-INJT-23's own folder
  (found by scanning the project for the ID, same as everywhere else in this project - never a
  hardcoded category path).
- `--command` - one command to test (e.g. `id`). Optional, and **additive** with `--command-list` /
  the auto-selected file, not either/or - every command collected from both sources gets tried.
- `--command-list` - override path to a command-list file, if you don't want the one implied by
  `--sys-type`.
- `--gadget` - restrict the run to exactly one gadget chain by name (e.g.
  `CommonsCollections6`, `Laravel/RCE1`) instead of the default, which is **every** gadget chain
  the underlying tool reports on its own listing (`ysoserial` with no args; `phpggc -l`).
- `--ysoserial-bin` / `--ysoserial-jar`, `--phpggc-bin` - override how each tool is invoked.
- `--timeout` - per gadget-x-command subprocess timeout in seconds (default 20).

Every gadget this run is using gets crossed against every command collected. A combination that
fails - wrong argument shape for that particular gadget, a missing dependency jar, etc. - is
skipped with a one-line reason and does **not** stop the run; sweeping "every gadget" rather than
one you already know fits is expected to hit a few mismatches.

**Output pipeline, always in this order, no flag changes it:**

1. Every successful gadget x command run's raw serialized bytes are saved first, as-is, to
   `Outputs/test_outputs/raw/<gadget>__cmd<NN>.bin`.
2. Every `.bin` file under that `raw/` folder - from this run **and** any earlier run, so raw
   files accumulate across `--language`/`--sys-type` toggles - is then read back and turned into
   two plain, one-line-per-payload wordlists:
   `Outputs/test_outputs/WSTG-INJT-23_url_WL.txt` (URL-encoded) and
   `Outputs/test_outputs/WSTG-INJT-23_b64_WL.txt` (Base64). Both variants are produced
   unconditionally for both languages - there's no `--encoding` flag, and neither tool's own
   native encoding flags (phpggc's `--base64`/`--url`) are used; this script derives both itself
   from the raw bytes so Java and PHP payloads end up the exact same shape. Both files are
   rewritten in full each run, so re-running after generating more raw material just picks it up -
   nothing needs `--force`.

**GUI side:** expanding WSTG-INJT-23's diagnostic-lights box shows an "Insecure Deserialization
(ysoserial / phpggc)" card right under the usual Copy/Build row, with a JAVA/PHP toggle and a
linux/windows toggle next to it - the OS toggle is also what implies `linux.txt` vs `windows.txt`
for the command list, so there's no separate control for that; it's just whichever file the toggle
points at. Command and Gadget override below are optional free-text fields matching
`--command`/`--gadget`. `POST /tests/:id/deser-run` (`lib/deser.js`) runs the script to completion
(same run-to-completion shape as the Error Handling wordlist endpoint) and the box refreshes
afterward, same as everywhere else that follows this pattern.

## Prototype Pollution (WSTG-INJT-22): wordlists + optional hash-fragment opener

Two scripts, one JSON probe list, and a dedicated GUI side panel (not a checklist-box section -
see below for why).

`tools/protopollution/proto_pollution_probes.json` holds the three probe sets verbatim as supplied:
`Body_Data` (5 `__proto__` JSON bodies), `URL_Hash` (14 `#__proto__[...]=...` fragments) and
`URL_Seg` (8 `?__proto__[...]=...` query strings). Edit this file to add/remove probes; both
scripts below just read whatever is in it.

**Script 1 - `tools/protopollution/protopoll_wordlists.py`:**

```
python3 tools/protopollution/protopoll_wordlists.py --project-root /path/to/Projects/MyProject
python3 tools/protopollution/protopoll_wordlists.py --project-root ... --max-urls 3
```

- `--project-root` (required) - scans for the `WSTG-INJT-22` item folder, same
  scan-for-the-ID-not-a-hardcoded-path convention as everywhere else in this project.
- `--probes` - override path to the probes JSON (default: the file above, next to this script).
- `--max-urls` - cap on how many target URLs `urls.txt` gets (default 5).

Writes `Body_Data.txt`, `URL_Hash.txt` and `URL_Seg.txt` to WSTG-INJT-22's own
**`Inputs/Wordlists/`** folder - deliberately not `Outputs/test_outputs/`, which is where every
other wordlist-generating tool in this project writes. `Inputs/Wordlists/` is what the existing
generic Wordlists panel in the detail column (`renderWordlists()`, backed by `lib/resources.js`)
already scans and renders with a Copy-to-clipboard button for any file it finds - so putting the
three files there, instead of building new copy-button UI from scratch, is what gets the "ez copy
to clipboard" behavior for free. The panel also shows a short note next to `URL_Seg.txt` ("use
this for testing requests in URL") and `Body_Data.txt` ("use this for testing body data"), and
`URL_Hash.txt`'s note points at the opener below.

The same run also tries to produce `Outputs/test_outputs/urls.txt`, by reading whatever Burp Proxy
XML is already on file in this item's `Inputs/XML/` folder (routed there automatically when you
add a Burp XML export via the sidebar - see "Burp Proxy XML" above). For each XML item, the
decoded response HTML is checked for a hash-aware page: either a non-empty anchor fragment
(`href="#..."`) or JavaScript referencing `location.hash` / `window.location.hash`. If any pages
match, up to `--max-urls` of **those** are written to `urls.txt` (most useful first - a page that
actually reads its hash is where a `__proto__` fragment has a chance of doing something client-side).
If none match but XML exists, it falls back to up to `--max-urls` **random** URLs from the XML
instead of refusing to produce anything. If no XML is on file yet, `urls.txt` is **not** written
at all (no empty file) and the run says so plainly - this file is only ever produced, never
truncated to empty, and the opener below treats a missing `urls.txt` as "run this script first,"
not as an error.

**Script 2 - `tools/protopollution/hash_fragment_opener.py`** (the "second script," entirely
optional - the three wordlists above are the real deliverable either way):

```
python3 tools/protopollution/hash_fragment_opener.py --project-root ... 
python3 tools/protopollution/hash_fragment_opener.py --project-root ... --delay 5 --payloads-per-url 2
python3 tools/protopollution/hash_fragment_opener.py --project-root ... --dry-run
```

Reads `Outputs/test_outputs/urls.txt` (from script 1) and `Inputs/Wordlists/URL_Hash.txt`, and
opens each URL in Firefox with one payload appended as the `#fragment`, to let you eyeball
client-side effects (XSS sinks, broken rendering, etc.) for each URL/payload pair.

**My interpretation of the brief, flagged explicitly here since the original wording
("open, one at a time, with a 10s delay... many urls can be opened same time... never more than
3x payloads to one url") reads as two different things depending on how you parse it:** this
script opens everything **sequentially** - one `subprocess.Popen` call, then `--delay` seconds
(default 10), then the next - rather than opening several URLs truly concurrently. I chose
sequential because it's watchable (you can actually look at each window as it opens, rather than a
burst of simultaneous windows), and because a clean mid-run Stop (used by the GUI panel below)
needs to interrupt between opens, which a sequential loop does cleanly via SIGTERM and a batch of
concurrent `Popen` calls would not. The 14 `URL_Hash.txt` payloads are distributed round-robin
across all target URLs from one continuously-advancing cycle (`itertools.cycle`), capped at
`--payloads-per-url` (default 3) opens per URL - so consecutive URLs get *different* payloads
rather than every URL repeating the same first three. **If you meant literally-simultaneous
windows across different URLs, this doesn't do that - let me know and I'll change it to spawn
each URL's batch without waiting on the others.**

- `--project-root` (required).
- `--delay` - seconds between opens (default 10).
- `--payloads-per-url` - cap per URL (default 3).
- `--new-window` - open a new Firefox window per URL instead of a new tab in the same window
  (default: new tab).
- `--browser-bin` - override the Firefox binary (default: `firefox` on `PATH`).
- `--dry-run` - print the job list and exit without actually launching anything, useful for
  checking what would open before committing to it.

Needs the operator's own desktop and a real Firefox - this is not something that runs headless or
makes sense to run on a remote box.

**GUI side - `public/js/protopoll-side.js`, a new top-level side panel** (toggle button in the
header, next to Reporting), **not** a section inside WSTG-INJT-22's checklist box. A one-shot
run-to-completion action (script 1) would fit fine in the checklist box, same as the Error
Handling and Deserialization cards above, but script 2 is a start/stop/poll background process
with its own `setInterval`, and the checklist box has no clean teardown hook for that timer when
the box re-renders or the item changes - so it got the same dedicated-panel treatment as the Mouse
Tool and Reporting panels instead (`setOpen`/poll-on-open/clear-on-close, mirroring
`reporting-side.js`). The panel has two sections:

- **"WSTG-INJT-22 wordlists"** - a *Generate wordlists* button that runs script 1
  (`POST /tests/WSTG-INJT-22/protopoll-wordlists`, `lib/protopoll.js`'s `runWordlists`,
  run-to-completion) and shows its log.
- **"Hash fragment opener"** - status dot (Running/Stopped), Start/Stop, and (shown only while
  stopped) delay / max-payloads-per-url / new-window controls, backed by
  `GET /protopoll/opener/status`, `POST /protopoll/opener/start`, `POST /protopoll/opener/stop`
  (`lib/protopoll.js`'s `startOpener`/`stopOpener`/`openerStatus`) - same spawn-and-track-in-a-Map,
  keep-the-record-with-an-`exited`-flag-instead-of-deleting-it pattern used by the Mouse Tool
  listener and the Reporting overlay, so a crash's error output (e.g. "run protopoll_wordlists.py
  first" when `urls.txt` doesn't exist yet) survives to the next status poll instead of
  disappearing with the process.

## Host Header Injection (WSTG-INJT-17): wordlist builder, reusing WSTG-INFO-04's own output

One script, one checklist-box card (run-to-completion, same shape as the Error Handling and
Deserialization cards above - no dedicated side panel needed here, unlike Prototype Pollution's
opener, since there's nothing long-lived to track).

`tools/hostheader/hostheader_wordlist.py` answers the question this was built for directly: **yes**,
the project's existing nmap data and subdomain-seeking output can feed this wordlist, and this
script does that automatically, reusing whatever **WSTG-INFO-04** (DNS / Port / VHost Enumeration)
has already produced for the project rather than asking the operator to re-type any of it. Every
one of these sources is optional and reused only if present - a brand-new project with none of
WSTG-INFO-04's outputs yet still gets a wordlist, just a smaller one (target URL, scope file if
any, the literal `*`/empty-Host entries, and the cloud-metadata/region entries).

Reused from WSTG-INFO-04 automatically (`--no-reuse-recon` turns this off entirely):

- **Subdomains** - `subdomain_seeker.py`'s own report (`Outputs/test_outputs/subdomain_seeker/
  subdomains_*.md`, newest by filename), its "Discovered Subdomains" table's Subdomain column.
- **Subdomain IPs** - WSTG-INFO-04's own DNS step (`Outputs/test_outputs/DNS_MODULE/results.txt`,
  the `dig` A/AAAA answers per domain) is checked first for each discovered subdomain; anything
  not already resolved there gets a live DNS lookup by this script itself
  (`socket.gethostbyname_ex` - no extra tooling), unless `--no-resolve` is given. This is a real
  DNS query against discovered hostnames at run time - turn it off if even that should be avoided
  for a given engagement.
- **Other in-scope IPs + their broadcast addresses** - every `<address addrtype="ipv4"|"ipv6">` in
  WSTG-INFO-04's two nmap XML outputs (`Outputs/data/uxp_scan.xml`, `Outputs/data/vhost_scan.xml`),
  parsed the same way `info10_collect.py` already parses nmap XML elsewhere in this project. For
  every IPv4 found (from nmap XML, from DNS results, and from resolved subdomains alike), the
  `/24` broadcast address is added too (`--cidr` to change the assumed subnet size) - nmap and dig
  don't report the real subnet mask, so this is a **stated assumption, not a measurement**.

Also added regardless of what WSTG-INFO-04 has:

- `--target-url` (required) and every line of `--scope-file` - defaults to WSTG-INFO-04's own
  `Inputs/Data/domains.txt` (the file its DNS step already treats as "domains in scope") if that
  file exists, overridable. Both are stripped down from a full URL to a bare `host[:port]`, since
  that's what actually goes in a Host header.
- `*` and a **literal empty line** for a null/blank Host value - Burp's Simple List payload type
  sends blank lines as an empty Host, so this is intentional, not a stray blank in the file.
- Cloud metadata (`--no-cloud` to skip): `169.254.169.254` - the link-local IMDS address AWS,
  Azure and GCP all share; there's no separate well-known IP for Azure or GCP - and
  `metadata.google.internal` - GCP's own metadata hostname (AWS and Azure have no hostname
  equivalent, only the shared IP).
- **The one speculative category here** (`--no-region-guess` to skip): common AWS/Azure/GCP region
  tokens (`us-east-1`, `eastus`, `us-central1`, ...) tried both bare and as `<token>.<target host>`,
  to see whether a region string in the Host header changes routing or cache behavior anywhere.
  Unlike everything above, which comes from data this project already collected, this is a guess
  with no evidence behind it for any given target - the original request itself ended this part
  with a question mark, so it's flagged here the same way: easy to turn off, on by default because
  it's cheap to try.

Every value collected above is also written in encoded form (`--no-encode` to skip) to
`Host_Values_Encoded.txt`: URL-encoded and double URL-encoded for everything, plus - for anything
that's a plain IPv4 address specifically - the same address again in **decimal** and **hex**
notation (`2130706433` / `0x7f000001` for `127.0.0.1`), both long-standing Host-header/SSRF
IP-obfuscation bypasses that don't apply to a domain name the way percent-encoding does. That's my
reading of "URL encode above, double, hex, decimal" from the original request - hex/decimal only
make sense for an IP, not a hostname, so that's where they're applied; flag it if a different
reading was meant.

```
python3 tools/hostheader/hostheader_wordlist.py --project-root /path/to/Projects/MyProject \
    --target-url https://example.com
python3 tools/hostheader/hostheader_wordlist.py --project-root ... --target-url https://example.com \
    --scope-file /path/to/extra_scope.txt --cidr 16
python3 tools/hostheader/hostheader_wordlist.py --project-root ... --target-url https://example.com \
    --no-reuse-recon --no-region-guess
```

Flags: `--project-root` / `--target-url` (both required), `--scope-file`, `--no-reuse-recon`,
`--resolve` / `--no-resolve` (default on), `--cidr` (default 24), `--no-cloud`,
`--no-region-guess`, `--region-list` (override the built-in region-token list), `--no-encode`.

**Output, same `Inputs/Wordlists/` placement as Prototype Pollution's three files, for the same
reason** - that's the folder the GUI's generic Wordlists panel already scans and renders with a
Copy button, so these two show up there for free:

- `Host_Values.txt` - every raw (unencoded) candidate Host value, deduplicated and sorted, with the
  literal empty-Host line appended last.
- `Host_Values_Encoded.txt` - the encoded variants described above.

A short provenance report is also written to `Outputs/test_outputs/hostheader_report_<stamp>.md`,
listing exactly which WSTG-INFO-04 sources were found/skipped and how many entries each category
contributed - useful given how many optional upstream sources this one pulls from.

**GUI side:** expanding WSTG-INJT-17's diagnostic-lights box shows a "Host Header Injection
wordlist" card right under the usual Copy/Build row - target URL field (required), an optional
scope-file override, the broadcast-CIDR field, and five checkboxes (one per `--no-*` flag above).
`POST /tests/:id/hostheader-run` (`lib/hostheader.js`) runs the script to completion and the box
refreshes afterward, same as the Error Handling and Deserialization cards.

## Injection Distributor (`07_Injection/inj_distributor.py`): category-wide wordlist seeding, now runnable from the GUI

This is an existing script in the project, not a new tool - but its ID mapping was wrong against
this project's own `wstg_reporting.json` (the file that actually drives the live checklist), badly
enough that it's worth documenting the correction prominently, the same way the Insecure
Deserialization section above documents its own WSTG-ID correction.

**What it does:** one script, run once for the whole `07_Injection/` category, that seeds every
*active* (not `skip=True`) `WSTG-INJT-XX` folder with a placeholder `Inputs/Wordlists/wordlist.txt`
and a what/why `Inputs/Data/<type>_injection.md`. It's one of only two real scripts in this
category - the other is `hpp_04.py`, the dedicated per-item HTTP Parameter Pollution tool.

**The correction (2026-11-08):** the script's internal `CATALOG` dict had roughly half its WSTG-IDs
wrong against `wstg_reporting.json` - not just an isolated slip. Its "01" was really SQL Injection
(properly `WSTG-INJT-05`), "05" was really LDAP Injection (properly `WSTG-INJT-06`), -15 and -16
were swapped (Request Smuggling / Response Splitting), real items `WSTG-INJT-01` (Reflected XSS),
`-02` (Stored XSS) and `-14` (Incubated Vulnerability) were missing from the catalog entirely, and
two entries - "Blind SQL Injection" and "ORM / GraphQL Injection" - aren't their own WSTG-INJT IDs
in this project's numbering at all (GraphQL has a real ID of its own, `WSTG-APIT-99`, in a
different category; blind SQLi is a technique within `WSTG-INJT-05`, not a separate item).

**The part that mattered most:** the old catalog had `WSTG-INJT-21/22/23` labelled Insecure
Deserialization, NoSQL Injection, and ORM/GraphQL Injection respectively - with 22 and 23 marked
*active* (`skip=False`). A plain `python inj_distributor.py` run would have written a placeholder
`wordlist.txt` and a wrong-topic `.md` straight into the **Prototype Pollution** (`WSTG-INJT-22`)
and **Insecure Deserialization** (`WSTG-INJT-23`) item folders - the exact two folders this
engagement's real, purpose-built tools (`tools/protopollution/`, `tools/deser/`) now live in. Both
are corrected and marked `skip=True` now, same as `WSTG-INJT-04` (HTTP Parameter Pollution,
`hpp_04.py`) already was. `WSTG-INJT-21` is correctly `CSV Injection` now (no dedicated tool for
it exists in this project, so it's active). The full corrected mapping, and which IDs are
skip/active and why, is documented in the script's own docstring - read that before editing
`CATALOG` again.

`WSTG-INJT-15, -16, -18, -19, -20` keep their `skip=True` status from before (just moved to their
correct IDs/content) - that was recorded earlier in this project as *"by design per the user's own
statement"*, i.e. a deliberate decision already confirmed with the operator, not something this
correction pass had grounds to second-guess. If any of those five turns out not to actually have
a dedicated tool, flip its `skip` to `False` in the `CATALOG` dict (or just use `--only` to include
it in a run) rather than trusting this script's silence about it.

```
python inj_distributor.py                               # write all active folders
python inj_distributor.py --dry-run                      # preview without writing
python inj_distributor.py --only WSTG-INJT-01,WSTG-INJT-11
python inj_distributor.py --list-json                    # print CATALOG as JSON, exit
```

**GUI panel removed 2026-11-08.** This project briefly had a top-level "Injection Distributor"
panel wiring the script above into the GUI (`lib/injDistributor.js`, `public/js/injection-side.js`,
`GET/POST /api/projects/:name/injection/*`). It's been taken out: `inj_distributor.py` only ever
writes placeholder payloads, and every WSTG-INJT item that matters now has a real tool - either its
own dedicated one, or the server-side/client-side wordlist orchestrators documented above. With
nothing left that genuinely needs a placeholder scaffold, the panel wasn't worth keeping. The
script itself is untouched and still runs from the CLI exactly as shown above, for the rare case of
a future WSTG-INJT item that doesn't yet have a real tool.

## Questionnaires

Several WSTG items are mostly a questionnaire, not a script run - "does registration require
vetting?", "is MFA present?", and the like. These are answered on the web, not run as a process:
there's no clipboard/hotkey dependency like Mouse Tool has, so there was no reason to shell out
to Python for it.

Two more read-only template files (same pattern as `injection_router.json` - operator-authored,
never written by this tool), in their own sibling folder, `Settings/Configurations/Questionnaires/`:

- **`questionnaire_router.json`** — which WSTG items have a questionnaire, and each one's runner
  script name (kept for reference; nothing here actually runs it). The runner name, minus its
  extension, is the questionnaire's stable `key` everywhere below - already unique, since an ID
  that appears more than once (`WSTG-IDNT-02` has two) has a differently-named runner for each.
- **`questionnaire_inventory.json`** — the same entries plus the actual questions, each with an
  `answer_type` (`yn`, `yn_unknown`, `yn_skip`, `flawed`, `choice`, `checklist`, `text`, `list`,
  or `auto` for something scanned from a Burp XML elsewhere, not asked here) and optionally
  `options`, `fields`, `condition`/`parent_condition` (show this question only once another one
  was answered a certain way, e.g. `"ATHN03-Item_1 == Y"`), `follow_up` (extra text prompts shown
  once a `yn` question is answered `Y` - a judgment call, since the data doesn't carry an explicit
  condition for these, but every `follow_up` in it reads that way), `is_gate`, `optional`, `note`,
  `reference`.

`lib/questionnaire.js` joins the two files by `(WSTG_ID, nth occurrence)` - the same rule the
operator's own `questionnaire_viewer.py` used - and finds each item's `Outputs/test_outputs`
folder the same way the rest of the app does: a scan for a folder named like the WSTG ID
(`resources.locateTest`), never a hardcoded category map. Three endpoints:

```
GET  /api/projects/:name/questionnaires            list, grouped by category, answered or not
GET  /api/projects/:name/questionnaires/:key       one questionnaire's questions + saved answers
PUT  /api/projects/:name/questionnaires/:key/answers   save (body: { "answers": { "<qid>": ... } })
```

Saving writes two files to that item's `Outputs/test_outputs/`, every time (not appended to):

```
<key>_answers.json   the source of truth - wstg_id, title, polarity, runner, saved_at, answers
<key>_answers.md      a readable rendering - every question, its answer, and anything skipped
                      by an unmet condition marked as such (never just omitted)
```

### Questionnaires page (GUI)

A "Questionnaires" pill in the workspace header opens a small info card (count of questionnaires
answered so far) with an "Open questionnaires" button to a full page
(`/project/:name/questionnaires`) - checkbox/text answering needs more room than the sidebar
panels give. On that page:

- the left column lists every questionnaire grouped by category, with a dot marking whether it's
  already been answered;
- the right column renders the selected questionnaire's questions by `answer_type` - radio
  buttons for `yn`/`yn_unknown`/`yn_skip`/`flawed`/`choice`, checkboxes for `checklist`, a text
  box (or two, for `fields`) for anything that needs typing;
- a question hidden by an unmet `condition`/`parent_condition` is shown as hidden with the reason,
  not silently removed, and reappears live as soon as the controlling answer changes;
- **Save answers** calls the `PUT` endpoint above and marks the item answered in the left column.


## Callback Suite (WSTG-CLNT)

A handful of WSTG-CLNT items (open redirect, resource manipulation, CORS, clickjacking, client-side
spoofing) need something hosted for the target application to actually call back to, plus a way to
see "did anything hit it" during an engagement. That's `server.py` - a stdlib-only Python HTTP
server the operator already had, now templated into every project the same way the Mouse Tool and
Questionnaires files are.

Two more read-only template files, same pattern as the rest, in their own sibling folder,
`Settings/Configurations/Callback_Suite/`:

- **`server.py`** — the catcher itself: serves the dashboard and payload pages, streams a live log
  over SSE at `/events`, exposes `/api/hits` and `/api/cj-list`, generates a self-contained
  clickjacking PoC on demand (`POST /api/generate-cj`), and logs every request to `server.log`
  in that same folder. One fix was made to the operator's original script: a request for the
  clickjacking generator's own folder (`/payloads/clnt-09-clickjacking/`) used to crash the
  connection with an unhandled `IsADirectoryError` instead of serving that folder's `index.html` -
  fixed by resolving a directory request to its `index.html` first, same as any other static
  file server would.
- **`index.html`** and **`payloads/*.html`** — the dashboard and the per-assessment payload pages
  (open redirect, resource manipulation, CORS, CSSI, and the clickjacking generator's own folder),
  copied in unmodified.

**This server is deliberately *not* loopback-only** - unlike the rest of this tool, it's the thing
the target machine is supposed to be able to reach during an engagement, so it binds the way
`server.py` always has rather than being forced onto `127.0.0.1`. That's intentional, not an
oversight.

### GUI

A "Callback Suite" pill in the workspace header opens a panel (same style as Mouse Tool) with:

- **Start/stop** - a port field and a button. Start calls `POST /callback/start` (spawns
  `server.py -p <port>`, tracked in memory the same way Mouse Tool's listener is - a server
  restart forgets it was running); Stop calls `POST /callback/stop`. `GET /callback/status` is
  polled every 4s while the panel is open and shows pid/port/log tail.
- **Open dashboard ↗** - once running, a link to `http://127.0.0.1:<port>/` that opens in a new
  tab. It's a different origin and port from this app, whose own CSP is locked to `'self'`, so it
  can't be embedded here - a new tab is the only honest option.
- **Export hits to WSTG outputs** - a button, not anything automatic. It calls
  `POST /callback/export`, which reads `server.log` from disk (works whether the server is
  currently running or not - no live hook into the SSE stream) and, for every request path it can
  map to a WSTG-CLNT item, writes:

  ```
  callback_hits.json   source of truth - wstg_id, total_hits, exported_at, and each hit
                        (timestamp, ip, method, status, path, note)
  callback_hits.md      a readable list of the same hits
  ```

  into that item's own `Outputs/test_outputs/`, found the same scan-for-`WSTG-XXXX-NN` way every
  other feature in this tool finds it - never a hardcoded category map. A hit on a path the mapping
  doesn't recognize, or one whose WSTG folder isn't in this project, is reported back (and in the
  CLNT-04 case, counted) rather than silently dropped.

The path → WSTG ID mapping (`PATH_MAP` in `lib/callbackProc.js`) mirrors the dashboard's own
`pathMap`/`siMap` exactly, so the two can't drift apart:

```
/payloads/clnt-04-url-redirect.html        → WSTG-CLNT-04
/payloads/clnt-06-resource-manip.html      → WSTG-CLNT-06
/payloads/clnt-07-cors.html                → WSTG-CLNT-07
/payloads/clnt-09-clickjacking/            → WSTG-CLNT-09
/payloads/clnt-13-cssi.html                → WSTG-CLNT-13
```

The old `questionnaire_viewer.py` (tkinter, read-only) isn't carried forward - there was nothing
it did that the web page doesn't, and no desktop capability (clipboard, hotkeys) it needed that
would have justified keeping a second, Python-only path.

## Threat Model (parameter-surface ranking)

For WSTG items where a traced HTML input tag needs to be matched up against the HTTP parameter
it most likely drives, `tools/param_mapper/` runs a two-stage, offline pipeline against a local
LLM and writes its answer alongside the other per-item outputs. Run from the command line, not
wired into the server:

```
python3 tools/param_mapper/param_mapper.py --project-root <project> --router injection_router.json --out param_map.json
python3 tools/param_mapper/threat_rank.py  --map param_map.json --project-root <project> --model qwen2.5:7b-instruct
```

- **Stage 1, `param_mapper.py`** - no AI involved. For every item in `injection_router.json`
  (a dedicated scope file, separate from `mouse_tool.json`: one XML index ↔ traced-tag-file pair
  per row, not just a WSTG ID) it finds that item's own `master_associations.json` (written by the
  operator's separate hover-trace tool), and for **every** association in it (an item can have more
  than one traced request/tag pair): extracts the URL/body/JSON parameters from the Burp XML
  request at that index, rebuilds the HTML tag from the hover-trace JSON, and - when the tag itself
  has nothing worth matching on (no `name`/`id`, just layout attributes) - pulls any `dataSources`
  entries that already trace the tag's value back to a specific URL parameter or storage key, so
  there's a stronger signal to fall back on than bare attribute-name similarity. One association
  failing (missing file, bad index) is recorded and skipped; it never blocks the others for the same
  item.
- **Stage 2, `threat_rank.py`** - reads stage 1's output and asks a local model, over Ollama's
  `/api/chat` with a forced JSON schema, to rank each request's candidate parameters by how well
  they correspond to the traced tag. The system prompt keeps this narrow on purpose: it's told to
  prefer a traced data source over name/id similarity when one is present, to give a one-sentence
  reason for every ranking, and never to evaluate security impact, suggest payloads, or discuss
  exploitation - "that is out of scope for you." Every parameter name the model returns is checked
  against the actual candidate list; anything that isn't a real candidate is dropped and recorded
  rather than trusted, and ranks are renumbered so there are no gaps. Ollama was chosen over vLLM
  specifically for the planned Mac move - vLLM has no Apple Silicon support at all, Ollama runs the
  same way on Windows, macOS and Linux.

### Running the AI stage on a different machine than the project tree

`threat_rank.py` normally needs two things at once: Ollama, and the project folder (to find each
WSTG item's own `Outputs/test_outputs/` to write into). If those two things live on different
machines - the project tree in a Kali VM, Ollama on the Mac host it's running inside, with no
network path deliberately opened between them - `threat_rank.py` splits into two pieces that
hand off a single JSON file manually (shared drive, USB, however you're already moving files
between the two):

```
# On the machine with Ollama (no --project-root - it never touches the project tree):
python3 tools/param_mapper/mac_threat_rank.py --input param_map.json --output MASTER_THREAT_MODEL_OUTPUT.json \
    --ollama-url http://localhost:11434 --model qwen2.5:7b-instruct

# Back on the machine with the project tree (no Ollama, no network call - pure file-shuffling):
python3 tools/param_mapper/import_threat_model.py --master MASTER_THREAT_MODEL_OUTPUT.json --project-root <project>
```

`param_mapper.py`'s output is already the whole project in one file (`categories -> wstg_id ->
[associations]`, every in-scope item from `injection_router.json` in a single pass) - that's the
file you hand off as-is, nothing upstream needed to change. `mac_threat_rank.py` is
`threat_rank.py`'s ranking loop with the project-folder half removed: it imports `rank_entry`
straight from `threat_rank.py` (one place owns the prompt/schema/hallucination-check, not two
copies that can drift), ranks every association in the input file against Ollama on `localhost`
only - no `OLLAMA_HOST` change, no VM networking, nothing exposed beyond the Mac itself - and
writes one `MASTER_THREAT_MODEL_OUTPUT.json` with every item's results in it. On macOS, leaving
off `--input`/`--output` opens the native choose-file/save-file dialogs (via `osascript`) instead
of requiring flags. `import_threat_model.py` is the reverse: no AI, no network, it just walks that
one file and writes the normal per-item `Threat_Model.json`/`.md` - same `find_wstg_folder`
scan-by-name as everything else in this project, never a path baked into the master file. The
files it writes are identical in shape to what `threat_rank.py` would have written directly, so
the GUI's Threat-Model button and backend route need no changes at all - they only ever read the
per-item file, however it got there.

Output, same two-file pattern as everywhere else in this project, written into that item's own
`Outputs/test_outputs/`:

```
Threat_Model.json   source of truth - generated_at, model, and one entry per association
                     (endpoint, xml_file, best_match, ranked_parameters, any dropped hallucinations)
Threat_Model.md      the same thing as a readable table
```

### GUI

The request viewer (sidebar → pick an assessment → the request pane + list underneath) now has a
thin button rail under it, one button per baseline category this item actually has a file for
(Raw / Authorization / Authentication / Input surface - whichever of those `xml_routing.json`
feeds this item and has a file on disk) plus an always-present **Threat-Model** button. This is
mostly just repositioning what already existed: `xml_routing.json` already handled an item fed by
more than one category (INJT under both Authorization and Authentication) with a toggle between
them - the rail is that same switcher, with Threat-Model added as one more option alongside the
baseline ones rather than a separate system.

Clicking **Threat-Model** swaps the list below it to the rows from that item's `Threat_Model.json`
instead of the raw Burp request list - one row per association, showing the method, path, and a
badge for the top-ranked parameter and its confidence (or "no match" / "—"). Clicking a row fetches
the real underlying request (resolved server-side from the file's own `xml_file`/`burp_index`
fields, never a client-supplied path, so this can't become an arbitrary-file-read) and shows it in
the same request pane as always, with a ranking strip above it: one chip per ranked parameter, the
top one visually marked, each chip's hover text carrying the model's one-sentence reason. An item
with no `Threat_Model.json` yet shows a plain note saying so, instead of an empty list.

New backend surface, read-only, both resolved through `resources.locateTest` the same way
everything else in this project finds a WSTG item's own folder - never a client-supplied path:

```
GET /api/projects/:name/tests/:id/threat-model                   -> { generated_at, model, items }
GET /api/projects/:name/tests/:id/threat-model/:itemIndex/request -> the request, plus { ranking }
```

## Push to Testing + Intruder Loader

Each row in the Threat-Model list now has a checkbox, plus a select-all and **Push N to Testing**
button above the list. Checking rows and pushing them converts those requests into one JSON file
in a shared queue a Burp extension watches, so the tedious part of Intruder testing - manually
pulling up each request and sending it over - doesn't have to happen by hand for every
injection-flavoured WSTG item.

**Where the queue lives, and the one rule that's non-negotiable about it:**

```
<INTRUDER_QUEUE_DIR>/<project name>/<WSTG-ID>__<random>.json         pending
<INTRUDER_QUEUE_DIR>/<project name>/processed/<same filename>        already loaded into Intruder
```

`INTRUDER_QUEUE_DIR` defaults to `IntruderQueue/`, a sibling of `Projects/` - not inside any one
project, because the extension watches one shared root across every project at once. But every
file written into it is still always under that project's own name as a subfolder, and only
that project's own requests ever go there - `project.name` is the same already-validated,
filesystem-safe name `lib/projects.js` uses everywhere else, so two projects' pushes can never
land in the same folder by construction, not just by convention.

**What's in a pushed file** - an array, one entry per pushed row:

```json
[{
  "host": "example.com", "port": 443, "https": true,
  "raw_request_b64": "<base64 of the exact request bytes>",
  "project": "GuiTM", "wstg_id": "WSTG-INJT-04", "xml_index": 1,
  "method": "GET", "path": "/search?q=1", "best_match": "q"
}]
```

`raw_request_b64` is base64, not plain text - the same choice made for `param_mapper.py`'s
`body_data_b64`: some requests carry bodies or encodings that aren't valid UTF-8, and base64 is
the only way to carry arbitrary bytes through JSON without quietly corrupting them. `host`/
`port`/`https` come from the Burp XML's own `<host>`/`<port>`/`<protocol>` fields when present;
if an export only has `<url>` (not every Burp-ish export is guaranteed to carry the others), it
falls back to parsing that instead of silently sending Intruder an empty host. A request Burp's
own XML already recorded as truncated (over `burp.js`'s per-request size cap) is skipped, not
pushed - a cut-off request would just break in Intruder.

**The Burp side** - `Settings/Configurations/Intruder_Loader/intruder_loader_extension.py` - is a
Jython extension, not something this app runs for you. It watches the whole queue root (every
project's subfolder, not just the one open right now), and for each file: decodes every entry's
`raw_request_b64` and calls `sendToIntruder(host, port, https, request)`, then moves the file into
that project's `processed/` subfolder so a Burp restart can never resend it (an in-memory
"already seen" set, the obvious simple version of this, forgets everything the moment Burp
closes - this doesn't). Burp has no API that lets an outside process load an extension into it,
so getting it running is a one-time, by-hand setup, done once in Burp's own UI (steps are in the
script's own docstring): add it under Settings → Extensions, then turn on "Automatically reload
extensions on startup". After that, every later Burp launch comes up with it already running -
including one started from this tool's own panel.

### GUI: Intruder Loader panel

A "Intruder Loader" pill in the workspace header (next to Callback Suite) opens a panel - same
shape as Callback Suite's:

- **Burp process** - Java binary / Burp jar path / optional project file, a **Save** button, and
  a **Launch Burp** / **Stop** toggle that spawns `java -jar <path>` and tracks it the same way
  Callback Suite tracks `server.py` (in-memory only; a server restart forgets a launch happened).
  This only starts the process - see above for why it can't do more than that.
- **Intruder queue** - a live pending/sent count for the current project, read straight off the
  queue folder (pending = files not yet picked up, sent = files already in `processed/`). Not a
  connection to Burp; just a directory listing, refreshed every few seconds while the panel's open.

New backend surface:

```
GET  /api/projects/:name/intruder-loader/config   -> { javaBin, burpJarPath, projectFile, extraArgs }
POST /api/projects/:name/intruder-loader/config
GET  /api/projects/:name/intruder-loader/status    -> { running, pid?, startedAt?, log?, queue }
POST /api/projects/:name/intruder-loader/launch
POST /api/projects/:name/intruder-loader/stop
POST /api/projects/:name/tests/:id/threat-model/push   body: { item_indexes: [...] }
```

## Findings Entry

A "Findings Entry" pill plus a **+** button sit in the workspace header, next to Intruder
Loader. The **+** opens a small floating window (not the sidebar - a quick "No" shouldn't cost
opening and closing a whole panel) that already knows which WSTG item is in question, because it
reads whatever's currently selected in the checklist:

```
CATEGORY:    Information Gathering
WSTG ITEM:   Conduct Search Engine Reconnaissance for Information Leakage
WSTG-ID:     WSTG-INFO-01
Findings?    ( ) Yes  (•) No
             [Confirm]
```

It has its own minimize button (collapses to just the title bar). **No** just closes the window -
nothing is written. **Yes** opens the Findings Entry aside with a blank data-entry form for a new
finding under that item, and the category/name/id it was confirmed against stay pinned to the top
of that form even if the operator clicks around the checklist afterward.

A WSTG item can carry more than one finding (two separate injection points found in the same
test, say), so the aside's default view for an item is a list of whatever's already recorded
there, each with **Edit** and **Delete** (delete needs a second click - the button turns into
"Confirm delete?" for one more click rather than a browser `confirm()` popup), plus its own
**+ New finding** button alongside the "+" in the header.

**The form, top to bottom:**

- **CVSS 3.1 matrix** - eight dropdowns (Attack Vector, Attack Complexity, Privileges Required,
  User Interaction, Scope, Confidentiality, Integrity, Availability), the same metric set and
  order as the published vector string. Once all eight are picked, `public/js/cvss31.js` computes
  the base score, severity band, and vector string live (pure FIRST.org arithmetic - see that
  file's `node --test`-covered unit tests, checked against two independently-known reference
  scores: 9.8 for the textbook unauthenticated-RCE vector and 10.0 for Log4Shell's published
  vector) - no server round-trip. The score and severity write straight into `Risk_Matrix`, so
  "it ends up Medium" really does end up as `"Risk_Level": "Medium"` in the saved JSON; the Risk
  Level dropdown is also editable by hand afterward, for a finding scored from an existing report
  rather than computed fresh here.
- **CWE information** - number, name, description, why it matters, impact.
- **Remediation** - a statement, a recommendation, and an **Additional recommendations** list you
  can add or remove rows from before saving.
- **Affected URLs** - likewise, a free-form list you add or remove rows from.

**Save finding** POSTs (new) or PUTs (editing) to the per-item findings route; **Cancel** discards
the form and goes back to the list. Same two-file pattern as everything else in this project -
`findings.json` is what the tool reads and writes, `findings.md` is the same content rendered
readable, both atomically written (`tmp` + rename) into that item's own
`Outputs/test_outputs/`, found the normal scan-for-the-WSTG-ID way, not a hardcoded category map:

```json
{
  "wstg_id": "WSTG-INFO-01",
  "findings": [{
    "id": "bc60d339",
    "created_at": "...", "updated_at": "...",
    "Risk_Matrix": { "CVSS_Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CVSS_Score": 9.8, "Risk_Level": "Critical" },
    "CWE_Information": { "CWE_Number": "CWE-89", "CWE_Name": "SQL Injection", "CWE_Description": "...", "CWE_Why": "...", "CWE_Impact": "..." },
    "Remediation": { "Remediation_Statement": "...", "Recommendation": "...", "Additional_recommendations": ["..."] },
    "Affected_URLs": { "URLs": ["https://..."] }
  }]
}
```

`lib/findings.js` sanitizes on every write - `CVSS_Score` clamped to `0–10` and rounded to one
decimal, `Risk_Level` nulled out unless it's one of the five real bands (`None`/`Low`/`Medium`/
`High`/`Critical`), every free-text field trimmed, every list field stripped of blank entries -
so a malformed or hand-edited `findings.json` can't wedge the GUI.

New backend surface:

```
GET    /api/projects/:name/tests/:id/findings               -> { wstg_id, findings: [...] }
POST   /api/projects/:name/tests/:id/findings                body: a finding, see shape above
PUT    /api/projects/:name/tests/:id/findings/:findingId     body: same shape, replaces that finding
DELETE /api/projects/:name/tests/:id/findings/:findingId
```
