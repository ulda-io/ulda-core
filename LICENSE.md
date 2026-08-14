# ULDA Core Community Source License 1.0

Version 1.0 — 13 August 2026

Copyright in the respective contributions © 2025–2026 Mark Shaposhnik and
Vitalii Radko.

Protocol concept and original implementation: Mark Shaposhnik.

Subsequent implementation contributions and improvements: Vitalii Radko.

## 1. Scope and acceptance

“Licensors” means Mark Shaposhnik and Vitalii Radko, each solely with respect
to the rights that person owns or is authorized to license in the Covered
Materials.

“Covered Materials” means the source code and generated bundles of
`ulda-core`, together with the ULDA Manifest, protocol documentation, test
vectors, examples, and other materials expressly identified as part of an
official `ulda-core` release distributed with this License.

Third-party materials and separately licensed files are excluded.

This License text is not a Covered Material and may be copied and distributed
verbatim.

This License applies only to `ulda-core`. Future ULDA libraries, servers, SaaS
or API services, container images, Enterprise products, and other separately
distributed products require their own terms.

By exercising any permission granted under this License, You accept its terms.
If You do not accept them, You may not exercise those permissions.

Nothing in this License restricts an act that applicable law permits and does
not allow the Licensors to prohibit by contract.

This is a source-available license. It is not an OSI-approved open-source
license.

## 2. Definitions

“You” means the individual or Organization exercising permissions under this
License.

“Organization” means a corporation, company, partnership, sole proprietorship,
association, foundation, non-profit organization, educational institution,
public body, government body, or other organized entity.

“Control” means direct or indirect ownership of more than fifty percent of an
entity’s voting interests or the power to direct its management or policies.

“Group” means an Organization together with every entity that Controls, is
Controlled by, or is under common Control with it.

“Modified Version” means a work that copies, adapts, translates, ports, or
modifies protected expression from the Covered Materials in a manner requiring
permission under applicable law.

“Core Functionality” means:

1. creating a private ULDA origin;
2. deriving a public witness;
3. advancing an origin or witness chain; and
4. verifying whether a candidate continues a previously accepted chain.

“Functionally Equivalent Offering” means a product or service whose entire or
primary purpose is to provide all or a material part of the Core Functionality
as:

- a standalone ULDA-compatible implementation;
- a port, replacement, or substantial substitute for `ulda-core`; or
- a hosted service or API that exposes that functionality directly to third
  parties.

“Ancillary Application” means a larger application whose primary purpose is
materially different from the Core Functionality and which uses ULDA only as a
supporting component for authentication, authorization, integrity, lineage, or
state-transition checks.

An Ancillary Application does not become a Functionally Equivalent Offering
merely because it calls the public `ulda-core` API or includes an official
bundle.

## 3. Community license

Subject to this License, each Licensor grants You, only to the extent of the
rights controlled by that Licensor, a worldwide, royalty-free, non-exclusive,
non-transferable, and non-sublicensable copyright license to:

- use and run the Covered Materials;
- inspect and study them;
- copy and modify them;
- create private forks and Modified Versions;
- embed them in an Ancillary Application;
- distribute them in source or bundled form;
- use them in paid products and services; and
- provide them as part of a hosted Ancillary Application.

You may exercise these permissions if:

1. You are an individual acting solely for personal, educational, research, or
   other non-commercial purposes; or
2. You are a Qualifying Small Organization under Section 4.

Commercial use is permitted for a Qualifying Small Organization.

You may keep modifications and the source code of an Ancillary Application
private. This License does not impose a source-publication requirement.

Every recipient must independently qualify under this License or obtain a
separate commercial license.

An end user who merely accesses an Ancillary Application and does not deploy,
integrate, modify, distribute, or use the Covered Materials separately does not
need to qualify independently merely because the Covered Materials are
delivered to or executed on that end user’s device.

Creating and maintaining a private Modified Version solely to integrate,
operate, secure, or maintain a permitted Ancillary Application does not by
itself create a Functionally Equivalent Offering. Offering or distributing
that Modified Version as a standalone ULDA implementation remains subject to
Section 5.

## 4. Revenue threshold

The “Revenue Threshold” is **USD 1,000,000**.

“Consolidated Gross Revenue” means the total worldwide gross revenue or gross
receipts of the Group before deducting costs, operating expenses, owner
compensation, contractor payments, or distributions. Bona fide transactions
between Group members must be eliminated to avoid counting the same revenue
twice.

Revenue must be calculated using the accounting standards legally required
for the Organization’s consolidated financial statements. If no such
standards apply, the Organization must use the method reflected in its
official tax filings or externally prepared financial statements. If none
exist, it must use a reasonable and consistently applied method based on its
ordinary books and records.

An accounting method, fiscal year, revenue classification, or business
arrangement must not be selected or changed primarily to avoid the Revenue
Threshold.

Taxes collected solely for a government, bona fide loans, equity investments,
and capital contributions are excluded. For each fiscal year tested under this
Section, an Organization that has no reportable gross revenue or gross receipts
must use its approved operating budget for that fiscal year.

Amounts recorded in a currency other than United States dollars must be
converted using the average European Central Bank reference rate for the
applicable period or, if unavailable, another comparable official central-bank
rate.

A “Qualifying Small Organization” is an Organization whose Consolidated Gross
Revenue:

1. did not exceed the Revenue Threshold during its most recently completed
   fiscal year; and
2. has not exceeded the Revenue Threshold during its current fiscal year to
   date.

If no fiscal year has been formally adopted, the calendar year applies. An
Organization that has not completed its first fiscal year is tested using its
current fiscal-year-to-date Consolidated Gross Revenue.

A freelancer or individual performing paid work is treated as an Organization
whether or not the activity is formally registered. Their revenue includes
gross receipts from all business and professional activities, but excludes
salary from unrelated employment. When the Covered Materials are used for an
employer or customer, that employer or customer must independently qualify or
hold a commercial license.

Revenue or activity must not be divided, concealed, transferred, or
recharacterized through members of the Group, contractors, accounts,
deployments, or other arrangements primarily to avoid the Revenue Threshold.
Affected revenue will be counted as though the arrangement had not occurred.

### Crossing the threshold

“Threshold Crossing Date” means the date on which an Organization that
previously qualified under this License first exceeds the Revenue Threshold.

Only an Organization that qualified immediately before its Threshold Crossing
Date receives 90 calendar days to obtain a commercial license or stop
exercising rights under this License.

Compliant earlier use does not become retroactively unlawful, and no
retroactive fee is imposed solely because the threshold was crossed.

The 90-day period does not apply to intentional concealment or material
misrepresentation of revenue, Control, or Group membership.

An Organization that already exceeds the Revenue Threshold when it first
exercises rights under this License must obtain a commercial license before
doing so.

### Returning below the threshold

An Organization may qualify again from the first day of a fiscal year if:

1. its Consolidated Gross Revenue remained at or below the Revenue Threshold
   throughout the immediately preceding completed fiscal year;
2. it remains at or below the threshold in the current fiscal year to date;
   and
3. it otherwise complies with this License.

Requalification applies prospectively. It does not cure a previous violation,
cancel an amount already due, or automatically terminate or modify an existing
commercial agreement. That agreement continues according to its own terms.

## 5. Functionally equivalent and competitive uses

Regardless of revenue, You must not use the Covered Materials or a Modified
Version as development, reference, training, comparison, testing,
benchmarking, validation, certification, debugging, documentation,
maintenance, or improvement material to create or provide a Functionally
Equivalent Offering without a separate written commercial license.

In particular, without such a license You must not:

1. use, modify, translate, port, or adapt the Covered Materials to develop a
   Functionally Equivalent Offering;
2. use the Manifest, protocol documentation, examples, or test vectors to
   develop or validate a Functionally Equivalent Offering;
3. distribute, license, sell, host, or otherwise provide a Functionally
   Equivalent Offering developed through a prohibited use of the Covered
   Materials; or
4. knowingly enable or assist another person to do any of the foregoing.

This restriction applies even when the competing implementation:

- is written in another programming language;
- uses a different internal architecture;
- has different public names or branding; or
- provides a material part of the Core Functionality sufficient to act as a
  replacement or substantial substitute for `ulda-core`.

This Section does not prohibit:

- ordinary use of `ulda-core` inside an Ancillary Application;
- testing that an Ancillary Application correctly integrates the official
  package;
- private security research that is not used to provide a Functionally
  Equivalent Offering;
- unchanged redistribution of an official `ulda-core` artifact in compliance
  with Section 6; or
- acts that applicable mandatory law does not permit this License to restrict.

For clarity, this License does not claim copyright ownership over an abstract
idea, mathematical principle, algorithm, interface, protocol behavior, or
functionality as such.

Similar output or behavior alone does not establish that the Covered Materials
were copied or used.

An implementation independently created without copying or adapting protected
expression from the Covered Materials, and without exercising permissions
granted under this License to develop, test, validate, or improve that
implementation, is not restricted by this License merely because it provides
similar functionality.

## 6. Distribution and notices

When distributing Covered Materials or a Modified Version, You must:

1. provide this License or an accessible link to it;
2. preserve copyright, authorship, attribution, and license notices;
3. identify materially modified files or portions; and
4. not represent a modified product as an official ULDA release.

For an embedded or minified bundle, notices may be provided in accompanying
documentation or a `LICENSE`, `NOTICE`, or `ABOUT` file. You are not required
to extract the bundle or publish the source code of the larger application.

Notwithstanding Sections 3 and 4 and the preceding notice requirements, GitHub,
npm, jsDelivr, unpkg, registries, mirrors, archives, proxies, security scanners,
and caches may store, inspect, cache, and transmit unchanged official artifacts
when the official package or release metadata provides an accessible link to
this License. This technical permission does not grant a recipient any right to
use the Covered Materials beyond the other terms of this License and does not
authorize a Functionally Equivalent Offering.

No rights to ULDA names, logos, trademarks, service marks, or other branding
are granted except accurate descriptive references that do not imply
endorsement, certification, or official status.

## 7. Commercial licensing, ownership, and other rights

A separate written commercial license is required:

1. after the Revenue Threshold transition period;
2. for a Functionally Equivalent Offering; or
3. for any use outside this License.

A commercial license covering all Covered Materials may be granted only by
Mark Shaposhnik and Vitalii Radko jointly, or by a person or legal entity
authorized in writing by each Licensor to license that Licensor’s respective
rights.

Commercial licensing inquiries may be sent to
[mark@shaposhnik.ch](mailto:mark@shaposhnik.ch). This address is an
administrative contact only. Correspondence does not itself grant any rights;
commercial rights arise only under a separate written agreement granted as
described above.

A future company may administer community and commercial licensing only after
receiving the necessary rights or licensing authority through a separate
written agreement. Such a transfer or authorization does not terminate or
narrow licenses already validly granted.

Commercial pricing, support, warranties, service levels, and payment terms are
governed by the separate agreement.

This License grants no patent license. It also grants no rights in future ULDA
products or other separately distributed products except as expressly stated.
All rights not expressly granted are reserved.

## 8. Termination and general terms

If You violate this License, Your rights continue if You fully cure the first
notified violation within 30 days.

An uncured violation, repeated material violation, or intentional material
misrepresentation terminates Your rights. Crossing the Revenue Threshold is
governed by the 90-day period in Section 4.

Upon termination, You must stop using and distributing the Covered Materials.
Rights of recipients who independently comply with this License are not
terminated solely because Your rights ended.

THE COVERED MATERIALS ARE PROVIDED “AS IS” AND “AS AVAILABLE,” WITHOUT
WARRANTIES OF ANY KIND, INCLUDING WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
PARTICULAR PURPOSE, TITLE, NON-INFRINGEMENT, SECURITY, ACCURACY, OR RELIABILITY.

TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE LICENSORS WILL NOT BE LIABLE FOR
INDIRECT, INCIDENTAL, SPECIAL, CONSEQUENTIAL, EXEMPLARY, OR PUNITIVE DAMAGES,
OR FOR LOSS OF PROFITS, REVENUE, DATA, BUSINESS, OR GOODWILL.

THE LICENSORS’ TOTAL AGGREGATE LIABILITY WILL NOT EXCEED THE AMOUNT PAID
DIRECTLY FOR USE OF THE COVERED MATERIALS DURING THE TWELVE MONTHS BEFORE THE
CLAIM. IF NOTHING WAS PAID, THE LIMIT IS ZERO TO THE MAXIMUM EXTENT PERMITTED
BY LAW.

This License is governed by Swiss law, excluding conflict-of-law rules.
Disputes are subject to the competent courts in Switzerland unless a separate
written agreement provides otherwise.

If any provision is unenforceable, it will be enforced to the maximum extent
permitted, and the remaining provisions remain effective. Failure to enforce a
provision is not a waiver.

A signed commercial agreement controls where it expressly conflicts with this
License.

The warranty disclaimers, liability limitations, governing-law and dispute
provisions, and obligations accrued before termination survive termination.

The Licensors may publish new versions of this License. A release remains
governed by the version distributed with that release unless You and the
applicable Licensors agree otherwise in writing. A new version does not
retroactively change the terms governing an earlier release.

---

**End of ULDA Core Community Source License 1.0**
