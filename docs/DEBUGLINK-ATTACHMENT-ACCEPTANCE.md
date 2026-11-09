# Opt-in debuglink attachment acceptance

**CONFIRMED implementation and A1–A7 runtime evidence; C1 integration pending.**
This record evaluates the complete attachment scope of issue #72, ADR-0004,
and ADR-0005.
It does not close the issue before final required CI and protected integration.
The separate GDB loader #107 is already integrated; see its
[acceptance record](GDB-LOADER-ACCEPTANCE.md).

## Final gate follow-up

**CONFIRMED Windows chooser correction; separate clean-launch click oracle fixed locally:**
At `ba65267`, run41897626643/job126818305192 passes the delayed-chooser control
and the first modifying Windows GUI journey: attachment, changed-curation refresh,
recovery and real active-validator cancellation. Independent retained-artifact
review and local Linux GDB replay verify four CLI/GUI generations, CRC rejection,
210 validator-log hashes and 631 protected Windows files. The job then fails its
second, clean GUI launch because an older control requires click counts `[1,2,3,4]`;
Windows correctly delivers `[3,4,5,6]` and two actions. The corrected oracle accepts
consecutive positive counts while retaining exactly one action per gesture. An
added primed real-click case reproduces the higher starting count locally; the
full actual-Java21 Linux GUI and both validator/GDB journeys pass. See
`docs/evidence/gui-click-count-offset-local-20261104.json`. **PRESENT, UNVERIFIED
on Windows:** the corrected clean-launch control. Full required CI and C1 remain
incomplete. The hosted GDB consumer was skipped; local replay is scoped evidence.

**CONFIRMED final-head Windows GUI test race; local correction validated:**
Run41890465382 at `edd3dce` fails Windows host job126794435767: the active
cancellation test selects the earlier decline request, then times out waiting for
a validator that was never launched. Its preview and screenshot confirm the wrong
selection. Native Windows long-path and CLI attachment checks pass in that run.
The chooser test now waits for Ghidra's asynchronous initialization, checks the
accepted file, and verifies intended review paths before confirming a target
change. A controlled delayed-listing regression reproduces the old selection and
passes with the correction. Actual Java21 Linux Script Manager export/preparation/
decline/cancellation, validators and both GDB journeys pass locally. See
`docs/evidence/gui-chooser-refresh-local-20261104.json`. **PRESENT, UNVERIFIED on
Windows:** the corrected chooser interaction. Final required CI and C1 integration
remain incomplete; #72 stays open.

## Evaluated revision and evidence

Production/test revision: `be2e806c31e7f60fee101a926e5d8b39c792888d`.
Hosted run: [41882141913](https://github.com/zwilcox/GhidraDwarfForge/actions/runs/41882141913).
The reviewed production JAR SHA-256 is
`80d57bb096febc46b8699d4205481a4c1219c7f59d9070880f72454d67e40b96`.
Ghidra 12.0.3, Java 21, Gradle 9.3.1 and the pinned libdwarf 2.3.2
producer remain unchanged. No new producer ABI is introduced.

Evidence is complementary: generic fault tests establish coordinator behavior;
native tests establish admitted filesystem behavior; real exports and GDB
establish valid executable/debug associations. None substitutes for the others.
Independent reviews compare actual retained bytes, sources, receipts, validator
logs and debugger transcripts, rather than accepting result labels alone.

| Record | Reviewed scope |
| --- | --- |
| [Package and native components](evidence/attachment-components-41882141913.json) | Exact packaged sources/JAR/Java bytecode and manifests; Windows native supervisor; native metadata/store/receipt observations, privilege restoration and 18 coordinator outcomes, including eight abrupt exits |
| [Linux targets](evidence/linux-attachment-41882141913.json) | Fifteen initial attachment/rollback/runtime cases: x86-64, AArch64, ARM32 and both MIPS32 byte orders, each ET_EXEC, PIE and no-build-ID; two saved-program changed-curation refreshes; eight abrupt recoveries |
| [Linux GUI](evidence/linux-gui-attachment-41882141913.json) | Unprivileged Script Manager, explicitly selected authorization, preparation, initial attachment, changed-curation refresh, saved recovery and actual active-validator cancellation; automatic GDB and CRC negatives |
| [Windows public journeys](evidence/windows-attachment-41882141913.json) | Native CLI and GUI initial/refresh/recovery/cancellation, Java21 long paths, 210 validator-log hashes, four positive GDB generations and four CRC rejections; 726 Windows evidence files preserved by the Linux consumer |

## Requirement audit

| ID | Implementation and acceptance evidence | Assessment |
| --- | --- | --- |
| A1 | `LinuxAttachmentHost` admits the documented local ext4 metadata profile; `WindowsAttachmentHost` admits fixed local NTFS with raw security preservation. Native metadata/visibility fixtures exercise supported preservation and unsupported metadata, streams, links and privilege refusals. Windows store fixtures prove sharing-lock refusal, independent backup, replacement and restoration with equal supported metadata; four raw metadata records are independently reconstructed. | **CONFIRMED** for the documented host contracts |
| A2 | Ordinary export has no attachment invocation. The separate helper requires a pinned request and explicit target-change confirmation after live validation. Both launchers and real Script Manager journeys exercise preview/default decline, explicit consent, preparation, fatal/cancel refusal and unchanged selected inputs. `AttachmentPreparationSmoke` verifies completed report/hash binding and refusal before a request is published. | **CONFIRMED** |
| A3 | `AttachmentPaths`, invocation/helper admission, `AttachmentExportBinding` and the live validator bind all selected artifacts, reports, tools, candidate and receipts. Protocol tests compare every selected role pair and reject direct aliases, hardlinks, leaf/dangling links and symlink/`..` traversal without changing sentinels. Operation/helper tests cover additional refresh/recovery/tool/cancel roles and output creation ordering. Logs use owned exclusive directories; the launcher opens no selected log. Retained native validator logs, file hashes and receipt chains are independently checked. | **CONFIRMED** |
| A4 | `AttachmentFileStore`, `AttachmentTargetStore` and native namespace adapters use exclusive independent backup and atomic replacement with metadata/readback checks. Existing backups, metadata mismatch, unsupported replacement and sharing locks fail without a copy fallback. Real cases preserve the original prefix except the three documented section-table fields, all program headers and payloads; backup identity differs from the replaced target. | **CONFIRMED** |
| A5 | The transaction persists verified recovery material and PREPARED before replacement, then COMMITTED or a recovery outcome. Generic tests cover every fault boundary, cancellation, receipt publication failures and concurrent targets. Eight native interruption cases per host cover initial/refresh PREPARED, TARGET_REPLACED, BEFORE_COMMIT and COMMITTED. Saved recovery is usable without helper stdout. Both real GUIs cancel after a validator PID exists and verify process cleanup, unchanged target and absent transaction outputs. | **CONFIRMED** for process interruption and documented flush mechanisms |
| A6 | Saved analyst edits are re-exported against the verified original backup with the strict imported-input hash guard intact. Linux exec/PIE and both Windows CLI/GUI journeys produce fresh pair basenames and changed CRCs, preserve original/prior-target backups and old pairs/receipts, and restore the old association through recovery. Missing/changed prior pairs, reused output paths and unrelated concurrent targets are refused. | **CONFIRMED** |
| A7 | All fifteen Linux target cases perform fresh automatic GDB discovery, exact objfile selection, source/types/arguments, stepping and normal exit, plus CRC mismatch rejection with fallback disabled. ARM/MIPS execute under QEMU. Windows-generated CLI/GUI generations undergo independent Linux GDB consumption with explicit source relocation and preserved downloaded artifacts. Default exports and declined/cancelled preparations preserve original hashes. | **CONFIRMED** for the recorded matrix |
| C1 | Current host/component/package jobs pass and their artifacts are reviewed. README, invocation/host documentation, TODO and context are reconciled with these results. The complete target regression lanes and final documentation commit's exact-head `required-validation`, followed by normal protected merge of PR158, remain mandatory. | **PRESENT, UNVERIFIED** until those gates and integration complete |

The current Linux extension job also passes protocol138, receipt105, file75,
target63, transaction532, export-binding30, operation103, invocation76,
helper229, preparation27 and recovery204 checks. Windows passes protocol138,
invocation76, helper229, preparation27 and recovery156; host-specific differences
are intentional and do not turn skipped Unix-only controls into Windows passes.
Both hosts pass the actual-Java21 supervisor's 38 checks. These counts identify
the observed suites; their source assertions and native/runtime evidence above
define their coverage.

## Boundaries retained from the design

Attachment remains an explicit target-modifying operation. It requires a final
sidecar beside the executable or in its `.debug` subdirectory, a compatible
named-section-table ET_EXEC/ET_DYN input with positive LOAD evidence, validated
export/report identity and supported native metadata. Unsupported attachment
layouts do not narrow ordinary export's sectionless/other-layout support.

Linux requires the documented ext4/protected-metadata visibility contract.
Windows requires fixed local NTFS and sufficient authority to inspect the full
supported security profile. Unsupported SACLs, streams, reparse points,
multiple target hardlinks and privileged/unsupported Linux metadata are refused.
Neither host silently downgrades preservation requirements or acquires authority.
OS authorization is requested only through the user's separate explicit choice.
The hosted Windows RunAs journey uses the runner's existing token; it does not
establish interactive standard-user UAC prompt/decline behavior.

Recovery evidence proves process interruption, native file force/directory flush,
and complete observed images with retained backups. It does not claim power-loss
survival on arbitrary storage or protection against adversarial filesystem races.
The candidate, target, receipts and sidecar are not one atomic multi-file update.
Previous committed receipts and generations stay immutable; automatic deletion
of retained generations is outside the selected contract.

## Integration closeout

The final documentation/evidence commit must pass the unchanged complete
`required-validation` gate, including every target lane and both host journeys.
Review its package provenance and terminal job results before merging PR158
normally against the current protected main. Record the final head, run and merge
commit in PR158/issue72, then close #72. This avoids treating a prior-head result
or an automatic merge request as completed integration. Release publication is
separate from this goal.
