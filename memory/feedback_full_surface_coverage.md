---
name: e2e coverage must span the full protocol surface, not just headline flows
description: Cotest's UI e2e suite is expected to cover the breadth of contrix functionality — chat/kanban/document/call/encryption/key-backup/recovery/webvh-rotation/moderation/audit/etc — not just 4-5 headline scenarios. Bound by spec sections, not by what's easy to write.
type: feedback
---

When designing or expanding e2e scenarios, inventory the **full spec functional surface** and propose a catalog that covers it — encryption, key backup, kanban drag/archive, document collaboration, calls, account recovery, WebVH key rotation, organization moderation, audit/erasure, attachments, push notifications, etc. Don't stop at headline flows.

**Why:** 2026-05-15 user pushback: "那么复杂的协议与实现, 为何你的测试只能写这么点点代码, 功能测试全了? 比如加解密? 比如密钥备份? 比如新建 聊天, kanban, 拖动 card..., archive card 等等. 用户创建, 密码找回, webvh 的密钥更新等等..." A handful of headline scenarios is not sufficient validation for a multi-protocol codebase.

**How to apply:**
- Start every "what tests to write" exercise with a **spec-driven inventory**: list every functional area the spec defines, then map each area to one or more scenarios.
- Scenarios should reach into encryption flows (MLS group setup, message encryption, welcome, key rotation), backup/recovery (passphrase backup, social recovery, device loss), per-content-type flows (kanban board with drag/archive/comments, document collaboration with cursors, call signaling), and admin/audit flows (organization moderation, GDPR erasure, audit log writes).
- The output of inventory should be a **scenario catalog** with priorities + dependencies + soland implementation status before committing to write code.
- Don't write 4 scenarios and stop. Write the catalog first, get sign-off, then execute in batches.
