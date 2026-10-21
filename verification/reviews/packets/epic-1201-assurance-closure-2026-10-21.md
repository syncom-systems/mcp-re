<!-- SPDX-License-Identifier: Apache-2.0 -->

# Epic #1201 (ADR-MCPRE-070) assurance-closure re-review packet: 70 theorems (2026-10-21)

Layer 1 (measurement). Candidate `exec/1201-pre-assurance @ 11d940f9`, the top of the PR stack
#1213-#1220. Baseline: `origin/main @ 8262c5fa` (v0.18.1), where all 133 then-active theorems were
REVIEW_CURRENT. At the candidate, `tools/verification/review` reports 135 theorems: **65 REVIEWED,
68 STALE_SEMANTICS, 2 UNREVIEWED** (THM-0135, THM-0136, new in this epic). On the specification axis,
THM-0101 and THM-0122 are STALE_CLAIM and THM-0074 is STALE_DEPENDENCY_CLAIM. **No specification
record, ruling or ledger line has been written for any of the 70.** This packet is for the owner to
ratify or reject.

## Method

Each re-review read the semantic-input diff of the theorem's moved units over `8262c5fa..6127939a`,
using the paths in `verification/policy/verification.toml` and the moved components that `review`
reports on the STALE_SEMANTICS line. `proof_dependencies` were read for proved and extracted
symbols, `governing_boundaries` against the `trust-boundaries.toml` diff, `mutation_probes` against
the probe diff, and test selection and sources for removed or weakened assertions. Every diff was
read adversarially against the theorem's statement, scope, `supported_by` and `depends_on`. The
commit `11d940f9` came after the review read `6127939a`; it is listed in the addendum below, and
every item in it was read the same way.

Verdicts:
- **CLEAN**: the proposition holds and the evidence still bears.
- **CLEAN-NOTE**: the proposition holds, and there is something the owner should see.
- **DISCREPANCY**: the claim or its evidence closure is no longer accurate.

Causes:
- **source movement**: code moved or the shared harness changed; the semantics are the same.
- **implementation change**: a supporting unit's behaviour changed.
- **dependency change**: a depended-on theorem, premise, boundary, proof dependency or shared crate input moved.
- **semantic claim change**: the theorem text moved.
- **missing review**: the theorem has never been reviewed.
- **pre-existing baseline debt**: none. Main was 133/133.

**Evidence class.** Every verdict below says the proposition holds against the code and the V0
evidence: tests, source scans, and structural and mutation probes. It is not a machine-checked
proof. Where a theorem's evidence includes Verus or Lean, the prover lanes must re-run on the
candidate in the closure run; this packet does not re-check a proof.

**Result: 0 claims false, 0 open discrepancies.** 57 CLEAN, 13 CLEAN-NOTE. THM-0122 was found as a DISCREPANCY: the claim said 'five events' where the code pins seven, the extension D1/Q3 authorizes. THM-0101 named a deleted symbol. Both claims were corrected in 11d940f9 and 6127939a under existing authority and are presented here for specification review at their new text. THM-0136 takes drafting fix D7 (11d940f9).

## Inventory: identities at 11d940f9

Fingerprints and review digests are from `tools/verification/review --fingerprint` at 11d940f9. A ruling that moves a claim (§Owner decisions 2 and 3) moves the affected rows, which must then be re-measured before records are written.

| theorem | proposed verdict | cause | origin | batch | theorem fingerprint | review digest |
|---|---|---|---|---|---|---|
| THM-0001 | CLEAN | dependency change (core proof_dependencies) | #1204, #1206, #1220 | B1a | `sha256:1ac678800a4ac149fcce2d7bb14c036a70e56e7e256fb13ad83e7d72807446f7` | `sha256:6914989e603689ce993ab85b8a4e6c943cf59d9052c34d18c66422416f712852` |
| THM-0002 | CLEAN | dependency change (core source_inputs) | #1204, #1206, #1220 | B1a | `sha256:6c7f4cd031295b9d15f280586f1021e387c4fe8bfd26f5cf2a1acf055dec4774` | `sha256:a9d97f5a3c0d2769597f44f99505dbca445fde31544e8cc84fad7cb0654339da` |
| THM-0003 | CLEAN | dependency change (core proof_dependencies) | #1204, #1206, #1220 | B1a | `sha256:0dfcfbd73ce6e43d1296c66d158e277a8a4f2b5e00ab020efbdd39069fb9e81d` | `sha256:151387ba41025d8b4ff2002f7a57dbf0e3fa69fb32b6f49cc96b1bd2802d9e65` |
| THM-0004 | CLEAN | dependency change (core proof_dependencies) | #1204, #1206, #1220 | B1a | `sha256:159cb32ef80b077028b7c113871408cac6fd85da123e28047eca989462e15b42` | `sha256:8ebe8ea80abf8b199b420c0e398bdbfa6955a9ca5b792662784ef0c045b6aae2` |
| THM-0005 | CLEAN | dependency change (core proof_dependencies) | #1204, #1206, #1220 | B1a | `sha256:aa09c2838cc3929109802d1031abc037d8d0a455e35444f72137b1ccbb7c9ee0` | `sha256:a7f27df95f5bc03dcc9afb836056bba4c1ac3f548cde6ef67a13cc032ac4569f` |
| THM-0006 | CLEAN | dependency change (core proof_dependencies) | #1204, #1206, #1220 | B1a | `sha256:858b9d7be9c726e564e1c11f99d89bf345a32573333a4fd838ab164b7e30906d` | `sha256:9124315cf8cf7189e8deb70ba76246cb47786959978a77db0791fc2f432bf09c` |
| THM-0007 | CLEAN | dependency change (core proof_dependencies) | #1204, #1206, #1220 | B1a | `sha256:ab73c764a7ac3b506b60e60cc899147b2522fa81997c7a5a0a7f8f9cec2321c2` | `sha256:d60d52b55e31d99081da787b4883b9d0b33db6b56034fc8ea7f3fb19e8e0c133` |
| THM-0009 | CLEAN | dependency change (core proof_dependencies) | #1204, #1206, #1220 | B1a | `sha256:f891aa87da728c7ffd2cd2e7ef98f0f60d8f8419c47a599616bbafa57ca4c171` | `sha256:58628dd53094d99b3525986ef540a8ea8fd5c36cd0118008b900efa6c23453f8` |
| THM-0010 | CLEAN | dependency change (core proof_dependencies) | #1204, #1206, #1220 | B1a | `sha256:69b6f32424f55fbaefb64d9eb94a7d2e39044e8cf082a51e77b696cf97033baa` | `sha256:0d5d600e788e11b399d16f5dac82c00ed8168db7dea63becbc23626e308530bc` |
| THM-0013 | CLEAN | implementation change | #1202, #1206 | B3 | `sha256:222ff157f0f34c256f60fa3a0c8d440cb509a4fc7a28098d89ea87358ef7880e` | `sha256:4606cf77c95d755cabd678ff043415a65a660be647a818bd0c4fb9d7a2321b14` |
| THM-0014 | CLEAN | dependency change (Core error.rs; freshness proof dependencies) | #1204, #1206, #1220 | B1b | `sha256:f88e7b44fb0fe96e8f4d05e7b702ff69c1e0af87f430504c1dd9a0a4d350f94b` | `sha256:42b666832fd94327f17ec2db93b7826fb1c11248d460f3d656568f382cf1e1ee` |
| THM-0015 | CLEAN | dependency change (Core error.rs; freshness proof dependencies) | #1204, #1206, #1220 | B1b | `sha256:8c665bf6363d6f554657b520e0e7d123829c12c4b00f12ecf03f881110bbfd62` | `sha256:ea5a016d14c417cd5194a1045013735997802636b3307df49a7a7552448fa10b` |
| THM-0016 | CLEAN | dependency change (Core error.rs; freshness proof dependencies) | #1204, #1206, #1220 | B1b | `sha256:72e76db6da1548a50619845474d28185c3866840ef3aa17c0f4ff85edd3badb9` | `sha256:ce8a72f97c617c3752603c09e9fb1bde7e062fe099607bdc37a4fc2858b0a8c4` |
| THM-0017 | CLEAN | dependency change (Core error.rs; freshness proof dependencies) | #1204, #1206, #1220 | B1b | `sha256:077bfbfcb16f265b1d0f72a147de16b82f859620e0a7c9fcf8fb54ca730613d1` | `sha256:1641e499332553225e49e5149191811b1043da2e98d863ecf9d282093ae1ea02` |
| THM-0018 | CLEAN | dependency change (Core error.rs; freshness proof dependencies) | #1204, #1206, #1220 | B1b | `sha256:00a2ad36b2e97cdd6c0d69ee2bac1f1481fc7431c0c5643f85011500a3f9c576` | `sha256:13b05667416a900c848abc472affb965c980bbcadd1505bc577de3a0ca6fcfea` |
| THM-0019 | CLEAN | dependency change (Core error.rs; freshness proof dependencies) | #1204, #1206, #1220 | B1b | `sha256:d8533de749f9b50c40ffc6d4ffbd3b2353e49e4b6619171ff2ad6f834d7fc70b` | `sha256:7e745ecd75e919f7ee416b6272c0732f4bce7215ddf396169798dcbc9bc9aeb8` |
| THM-0020 | CLEAN | dependency change (Core error.rs; freshness proof dependencies) | #1204, #1206, #1220 | B1b | `sha256:a176280bae758572695206bbce4e0f08e95b87034a45dbe7d4139c4001a7ef1f` | `sha256:92cc93b13bc2fbb14287414183c99c37fe3861536b3ef8868a07ef9e143e2bc1` |
| THM-0021 | CLEAN | dependency change (Core error.rs; freshness proof dependencies) | #1204, #1206, #1220 | B1b | `sha256:4af426ca8dcb0f332926ce7e2a8e8cd241f41b53fc857aebecc7b84e1a950c84` | `sha256:8da02acfcc8d044e54c00d2ea028882f2d4a067338afcccdf81b89bbc5e894ef` |
| THM-0022 | CLEAN | dependency change (Core error.rs; freshness proof dependencies) | #1204, #1206, #1220 | B1b | `sha256:26250e9cf23da4a0da6e266bdfa6b156d75b95ce40d161780626cbef8f0813f2` | `sha256:7f697ef12b6861dbc008b6f317e707d7b46dd45287d797b48f6c44974098634a` |
| THM-0024 | CLEAN | source movement (shared harness) | #1204-#1206 | B4 | `sha256:49de376b15e2eccb2dc8cba1c7b31a9c56fdd623ecc92731152b6ce03ce79893` | `sha256:801197cd611fe545316cc6e5801ab9eeaf015e15817ff5aa1352a9d4a2cb93ac` |
| THM-0026 | CLEAN | dependency change (boundary.tls_mechanism digest) | 37b522b2 | B4 | `sha256:fc7c6804aca29d3e8a24b1dfd31ff1e19f7f0085420584b26ada532d5e160362` | `sha256:dd12f58d691efd507a7352ad43e2935135707144c8f8415bcd2e099ce937926b` |
| THM-0027 | CLEAN | dependency change (boundary.tls_mechanism digest) | 37b522b2 | B4 | `sha256:faec59e583744094ecf8211cf8d49171e08a0f416cd131d25c4f50a539bd2a50` | `sha256:930860c9ee2f470e74b5d69ae0bdea043d6fa9b633139c623e6f3d7228f3e7cd` |
| THM-0032 | CLEAN | source movement | #1202, #1204, #1205 | B5 | `sha256:91e09c858b7982304cf7a13aa75ba2827b6852348c2a4aa4d311dfcf3a644be4` | `sha256:6c35cd28b0fc162d7d875258990ccc490f075e2eed050a1e80713673b5376c09` |
| THM-0038 | CLEAN-NOTE | source movement (root split into app/entry.rs); guard extended in 11d940f9 | #1206, 11d940f9 | B3 | `sha256:2f38be9ca9fedba5b2421acc9968c31691003fb56c4878a1bbdb0b6872dd01bc` | `sha256:ddac7d8d5bbb8c24be0455ca6357a29724ff0538f3de33167572431d95cf3f39` |
| THM-0040 | CLEAN | source movement | #1202, #1204, #1205 | B5 | `sha256:4c5d90700148aa8e237985e63f5fef13b281746c45bbf1a33d51fafbab2f8fd3` | `sha256:be3644d2e34fb1b85c661872322485b3032b5eba992fbe91789fa6c9e7c80fe7` |
| THM-0043 | CLEAN | source movement | #1205, #1220 | B2 | `sha256:34353106aaab2d0426aca7c3dc87b7fd1051ad109112c70969dff6a1c976e993` | `sha256:222a2c6551fd50b492b494adce680325e71ba93a332d469909f5432ee8dab8a2` |
| THM-0044 | CLEAN | source movement | #1205, #1220 | B2 | `sha256:a2c4aa5807f9e176b087536f20a8b260e606cd4785b9c072f9552f4a9e14c734` | `sha256:754a1a2f9209e3c42c5ebf3742c2d6bf4658f729090c3d8efc1a405c34f8f223` |
| THM-0045 | CLEAN-NOTE | implementation change (G1) | #1204 | B2 | `sha256:a3677e05cf813f666f25d0febdbcedbf1982d1fad439344bec1aa977f0e27684` | `sha256:732d90912725c45557822383e29d5d36e7c3bd3c3ffea7b7f4dc9c504b29e9b3` |
| THM-0048 | CLEAN | dependency change (boundary.tls_mechanism digest) | 37b522b2 | B4 | `sha256:36d8b72301e9dacf16480f987b6331c2d9a2601fcc78b67e1e0ec0c7fa7383d8` | `sha256:ed7535fc1c8a5c0c8221e4ccb3fcf1e2e47895fb90ebe2b6d013527a6f245189` |
| THM-0051 | CLEAN | implementation change | #1204, #1205, #1220 | B2 | `sha256:cc371a5dbf05380e021b79d0b7d3017444e9d8916df2d8bce7c13747de4fe7ba` | `sha256:ac45c5e4ece6bfc97a74061e718e8936b31228829da4a8bf1545b3558b4aefd4` |
| THM-0052 | CLEAN | implementation change | #1204, #1205, #1220 | B2 | `sha256:597274da4b9339e7d1c77af527ef71b4aee5fa0742243dee1b85e2d4af2fbba8` | `sha256:9f959fb4f501a5e98dd007d81a858e634379d53148142081318fe7cd010cc978` |
| THM-0054 | CLEAN | dependency change (boundary.tls_mechanism digest) | 37b522b2 | B4 | `sha256:ca274e81669473a92ae8f64f2a2bf68ce443211586c540fa60f9346f4fb7b065` | `sha256:3bd18eb91fa7d6279e1f74e465392c2865900a55df0173ed403c16f613da882a` |
| THM-0062 | CLEAN | source movement (test lane) | #1204-#1207 | B3 | `sha256:e87e43867b5c6882c43d636703e6d7cc860808cd62d2e4fb060a8a46b6a8f5b9` | `sha256:2dbb2d062d0e19078bcfc79a49a184bfef8a4848b651fc95543d4c43e4ac2d7c` |
| THM-0063 | CLEAN-NOTE | implementation change | #1202 | B3 | `sha256:8871ed21a3b398b625c1c4b3f8674e8f0d93e34a2f56929456b3d43f87e126e7` | `sha256:4e04507b6c77bf84f35c51d70fda5d1be54df6a37d751adaef2094589d3c0dee` |
| THM-0066 | CLEAN | implementation change | #1202, #1206 | B3 | `sha256:2426e6c26764233a4fbf79c8e97aa61fda247f823baaeda620b6d76f7edbca25` | `sha256:2e7f78278949993d399cb95e707010960c70c887fb5b0458d4686f93e61b58a3` |
| THM-0067 | CLEAN-NOTE | source movement (root split into app/entry.rs); guard extended in 11d940f9 | #1206, 11d940f9 | B3 | `sha256:db84c710a7de60e21701ce69d1e5605d62e86e38c813c85baf48e7ce4307e9da` | `sha256:52c12f4824493a391c7f21436de302648662593a0f5a77a0fb93a84841d5c9e3` |
| THM-0069 | CLEAN-NOTE | source movement | #1202, #1204-#1206 | B5 | `sha256:0ce3b80720627213892793e307cc1ac56e91f4f0c310bdfc4049785deac38e0a` | `sha256:fa68143036085fc2d3042d9fd57859368045d2368bc380c524b8cbc0b3d661db` |
| THM-0070 | CLEAN-NOTE | implementation change | #1202, #1203, #1206, #1220 | B6 | `sha256:dd38b842fb857af412fae0c08d241373fd6f7dcec05c3ac7802ca72b7e5269e1` | `sha256:70c3a0d367b0efc68431af45775f645aa4e783ff873ddcf441bfd71c6b03d7e5` |
| THM-0073 | CLEAN | implementation change | #1202, #1206 | B3 | `sha256:14a931f5c1cfa81f9a4d9d82cec8500d4916cabb86ca9a95b1666e25ee483159` | `sha256:7cea3207097fbcc9cbe8fc0fb5db43b4dba8ce6cd7948fb684f05cdf08832087` |
| THM-0074 | CLEAN-NOTE | dependency change (THM-0101 claim) + implementation change | #1204, 6127939a | B2 | `sha256:9e35e992b57f53de19ca6d9c2d400a41bbb4e06ee404c408fa26e28e8615b20e` | `sha256:aa5a683a7acbc633b8f2397dd94d8f0ec0f07b4149ec3aa4ea614ab9af5881aa` |
| THM-0075 | CLEAN | implementation change | #1202, #1206 | B3 | `sha256:1403c470b204923e967695ee75692c0cc31e01df03d25d15cde7c60554f66724` | `sha256:9fcb666533112df733d2d8532788b279c19f1bb37b4ed08384bfc147769b7bac` |
| THM-0077 | CLEAN-NOTE | implementation change (audit posture) | #1206, #1220 | B5 | `sha256:9412e9593b1981a0f89dba3de90cd81583948d38b5775185d3de2b7ce289316f` | `sha256:1c5362309196a83252eedd853be1ea387c49dd9bf7c95b8bbb2e15d5b469e7be` |
| THM-0078 | CLEAN | implementation change | #1204, #1205, #1220 | B2 | `sha256:cff60d495309322415f35b64332c52faf3f9a416e58275230281f6c10ff6c6b4` | `sha256:dc3dd379ba0317c738281acffd27ae3454925d109588b7406fa574d1fb63d87d` |
| THM-0080 | CLEAN | source movement (shared harness) | #1204-#1206 | B4 | `sha256:e5fd5b87e8c336c522e5cb2f865ccf86a3983b80851c14390c270931ad2197b0` | `sha256:11625925c83c710f85ec2ee2b79f9ae37d20fa1389e916bf0e4992a26f9c95ae` |
| THM-0081 | CLEAN | implementation change | #1204, #1205, #1220 | B2 | `sha256:bf723ba252cf5ed8ae595e4e7db470ecc277a5c56d7a64eb0c5c236b1b93ee86` | `sha256:e80ca9c91e3c566e0c4ee15c00f604446b477866c75b69a71d0d69753f433c95` |
| THM-0082 | CLEAN | implementation change | #1202, #1206 | B3 | `sha256:3f5a3cf9b340ccc1afcdda33834c1d5cfaa3200d3ba804060bbbd64352dd3b6a` | `sha256:0125c0a21a79f283314fea2ea2076e87273695dada5ce1d513ad88f24e52ec9e` |
| THM-0083 | CLEAN | source movement | #1202, #1204, #1205 | B5 | `sha256:f51f19ff25e327d0839275a5da3ecb0f589d5eec151b7da0da841a3e6c51620d` | `sha256:10d9d3d489eabc490afdf99b51afe8e6a81dca155e498f0b8b48f93ebb1f4e14` |
| THM-0085 | CLEAN | implementation change | #1202-#1206, #1220 | B6 | `sha256:f39497f8ded64f01ddd3473783578ac80f0419bc6d4c875ae833319bdda0005f` | `sha256:85717f2ed259befa1b795b138bd5e052849d0b28236195463dc5b86864231286` |
| THM-0088 | CLEAN | implementation change | #1204, #1205, #1220 | B2 | `sha256:4cd3913879e3417cf9ed65cb92ebb373685c2971c7617b6bb06d8c9d1cd21fe0` | `sha256:a7c9d1c94b50c279be58f47621f63e9b2d5e42179ee2c9302a8ca47867b1f760` |
| THM-0089 | CLEAN-NOTE | source movement (shared harness) | #1204-#1206 | B4 | `sha256:e72c8e86f82919aa6ff4b0e74981dfdd72fe41bb0147193e8bddc1b0d297d4c3` | `sha256:2e8960e252cef4c0ec1a03ea951dd45a90d504cb0e8554babb164916e113a913` |
| THM-0090 | CLEAN-NOTE | implementation change (TLS connector) + dependency change | 37b522b2 | B4 | `sha256:ce22a7ec651a2fbdc6bf3f8083a57b398a12164a06108086209e4099aad34d9d` | `sha256:cbfff8287677908d2fe8dec34e2f7d205911df5ab19bb494c32fd7f2edc36654` |
| THM-0092 | CLEAN | source movement (shared harness) | #1204-#1206 | B4 | `sha256:49569e318ea23f11449d3e262a2be902b477bb8e2c189576ed6271cc62b1f4db` | `sha256:5460791b69e7f531d0796ff27a96b3dc1a2de7c0fa038e0b1f42bffbae570cb9` |
| THM-0093 | CLEAN | source movement | #1202, #1204, #1205 | B5 | `sha256:1f65ea3aeacc3fc87d5b3d276c939d4f32b7752fb11f0f158e6c60ae1ea49a18` | `sha256:8aaacb1bcda3ead0566c3d5a698860c462f81789294b22a614ec04647563989f` |
| THM-0096 | CLEAN | implementation change (collateral, app.rs) | #1202, #1206 | B5 | `sha256:97fb6e966903e09f0e9fedf634f46a536bafa48384318a88200955a692e4ad4a` | `sha256:073a5d379fe81cd0e823cc209e1a21cdc88f8daae1ca93d62db9b2ffa6d7a74c` |
| THM-0099 | CLEAN | implementation change | #1202, #1206 | B3 | `sha256:91c7d9e6c56d998af846af3dda4bf516dee04b2638a826a22f51c0fc687605f1` | `sha256:75c7eef094351d03509d6bcaeba770804ef89c8e8159adaa392e64b44fb5b0f2` |
| THM-0100 | CLEAN | source movement (shared harness) | #1204-#1206 | B4 | `sha256:5027b6a894e9091efbab423fa9be5cd729f37acd5c2af8acc311977c5b9fc199` | `sha256:69c6c13793f7bf1275ef524c82581ec940ad135450977a930cc094f39a1d4f3e` |
| THM-0101 | CLEAN, claim corrected | semantic claim change (symbol only) + implementation change | #1205, #1220, 6127939a | B2 | `sha256:4dc7e4a70e82dc5fd1ba9638b5d4ce1f2582494e736d3f700d9ba6e6f202a96c` | `sha256:5c17bcee67cf962de77f8905d81e8974e7c81156ff99f36e02d615d83ec5b7ca` |
| THM-0102 | CLEAN | source movement (shared harness) | #1204-#1206 | B4 | `sha256:34c89b238de94e4c0cf1505506fa416c81437b8e188f879820370d34eb43aaac` | `sha256:dda82bd8079c7a97d68a8b281fae87aa6a59ddd1b537fbb38fe4f4e11e1517ed` |
| THM-0103 | CLEAN | dependency change (boundary.tls_mechanism digest) | 37b522b2 | B4 | `sha256:9855fe8152cefc4d7d6e12446a8afaa805875d29976fcb1a5fc98b2c3e376a57` | `sha256:72c8a12b1568f6ddf6d6b69efd0baaf8ce2cc972b9367e16d74739748725eda6` |
| THM-0109 | CLEAN-NOTE | dependency change (boundary) | 37b522b2 | B4 | `sha256:6b80104b3451c66b895d9ec9d87c236ffde93df69c511477a7905047e03f7bbd` | `sha256:358677587bcc3da55f27b7cd4245acc4bea64ff6e06507702607919ff47c700b` |
| THM-0111 | CLEAN-NOTE | implementation change (new verdict token) | #1204, #1206, 37b522b2 | B1b | `sha256:f3f5713603a624cc6836ed1928f42ebbb45a5401b1a111194ced0f6e6a1f7d3c` | `sha256:9c551b77f43d569f225329a7b5179bf742b993a6e1bfa513624c01e186f876e2` |
| THM-0112 | CLEAN | source movement | #1202, #1204, #1205 | B5 | `sha256:29c9bb8d600e2fa44bd5d4ef34495a8a46f62b9b28e02bde575c1fa9a6b31b9e` | `sha256:0dfded8e9d452f00e359bb6ee8bb5ee9361ca8a1f7d459bbb228488362b6087c` |
| THM-0113 | CLEAN | source movement | #1202, #1204, #1205 | B5 | `sha256:95c28f72283a689eaeaf430a7942e8a483e6cb5231168fb6c568d562558f76f4` | `sha256:7056cef2edd0cbb7f245dec1a64b7a67202879b81f3a6988fc27f82ef73959d2` |
| THM-0122 | CLEAN after correction | semantic claim change (count corrected in 11d940f9) | #1204, #1206, 11d940f9 | B1b | `sha256:c88332a76128e15a8f704754e3871ac787819d986fb67a1409d3fad36176544e` | `sha256:5cfdfae9f28286b314cf0820d7863705beeb78e09dd1505894e8275ca17419c5` |
| THM-0128 | CLEAN-NOTE | dependency change (core source_inputs) | #1204, #1206, #1220 | B1a | `sha256:32037a30267a670712b7eca3b024df4dbdd20f1b993036d63d0283fa4ad628e4` | `sha256:a57d81dfa912f7d9e9a260e97235c02369d72aeb6b9b704626f1f5f64831ae29` |
| THM-0129 | CLEAN | source movement | #1202, #1204, #1205 | B5 | `sha256:8531b9c45bd24aae09b1a08492798262574d3abe4a4f7a62ed1ca3aa725a681b` | `sha256:198d5449c56b316476968a49ee04e88faa06069a25d24e65eb35c178f063212f` |
| THM-0131 | CLEAN | source movement (shared harness) | #1204-#1206 | B4 | `sha256:9db314ae680c138e672f2a7be0169f06be6f03f0cf26494ccdacd83c21942e8f` | `sha256:d9d8b2e468b0dea68f0db50e0a974dfca96a85bb02a6e93712661b4e49eed912` |
| THM-0132 | CLEAN | source movement | #1202, #1204, #1205 | B5 | `sha256:cedf63cdb0ad2b7fbbacc1c75c34b92657eaf35cfc7bc05f4ab85dc7148f1a68` | `sha256:59f49835d213c62ff4291e3d8999af6c518f91e00665d935170e48e827f1aa06` |
| THM-0135 | CLEAN | missing review (new) | #1204-#1207, #1220 | B6 | `sha256:df790c7b287331ca3f4924495e606485937e432de42f4e938d9eb58936bbeaae` | `sha256:84e8310d7c7151e4f46d3c7c4eb377ae858d6ef7615ebda87927bda153147f94` |
| THM-0136 | CLEAN after D7 | missing review (new) | #1205-#1207, #1220, 11d940f9 | B6 | `sha256:fe590f851402e2c61057a67d2c60a6534acebec3ffd406b3e73555c5a4f63e90` | `sha256:18538f30c76aae9a9e9d5ff78f9474dbe347098dc1c7e43ff80e951d8a58a661` |

Cause totals: dependency change: 26, implementation change: 19, missing review: 2, semantic claim change: 2, source movement: 21.

Assumptions (no record yet; first review): **ASM-0089 CLEAN**, **ASM-0090 CLEAN after D8**
(11d940f9), **ASM-0091 CLEAN**. Text identity is the entry at 11d940f9.

Existing assumptions whose own review trigger fired, though their entry text and digest did not move:
- **ASM-0070**: rustls-webpki 0.103.15 to 0.103.16 (RUSTSEC-2026-0382). The bump only narrows what is accepted.
- **ASM-0082**: the outbound agent is now built with `tls_connector(RootedConnector::public())` instead of ureq's `tls` feature.

Both need an owner re-acknowledgement. The premise text still holds for both.

## Addendum: 11d940f9 against the reviewed 6127939a

| change | units/claims moved | read |
|---|---|---|
| THM-0122: "exactly five" becomes "exactly seven", naming the execution intent and the accounting record. M349's conjunct follows. | THM-0122 claim; `conformance.audit_vocabulary_drift` mutation_probes | The proposed text from B1b. The guard pins all four sets exactly. |
| THM-0136 scope (D7): "entered only through the carrier ... whose event alone the publication reads"; "source-scan tests in". | THM-0136 claim | Agrees with THM-0101's corrected text and with `exchange_state.rs:365-374`. |
| ASM-0090 justification (D8): adds `ApprovalSpentNothingExecuted` to the pre-dispatch dispositions. | ASM-0090 digest, which reaches THM-0135 and THM-0136 premises | Matches `exchange_state.rs` refusal dispositions. |
| `composition_raw_read_test` scans `app.rs` and its `app/` subtree. | `proxy.trust_composition_root` test sources (THM-0038, THM-0067) | Resolves the B3 CLEAN-NOTE. Poison pill: a raw `values.` read in `app/entry.rs` is red, naming the field. |
| `the_three_halves_are_distinguishable` is renamed `the_four_halves_are_distinguishable`. | `core.audit_vocabulary` test selection | Name only. |
| Carrier wording in `exchange_transition_ownership_test.rs` doc comments. | `proxy.exchange_transition_ownership` test sources (THM-0101) | Comments only. |
| Two unit descriptions; two workflow comments. | none (not fingerprinted) | |

## Owner decisions this packet does not take

1. **Ratification of the 70 verdicts above**, and of ASM-0089-0091; re-acknowledgement of ASM-0070 and ASM-0082.
2. **THM-0077 support (B5).** The required audit posture's no-downgrade controls are in `proxy.audit_posture`, which supports THM-0135 and THM-0136 but not THM-0077. Recommendation: add `unit://proxy.audit_posture` to THM-0077's `supported_by`. This moves THM-0077's claim.
3. **Root attachment of THM-0135 and THM-0136 (B2).** Neither is in any declared root's dependency closure. D10 forbids revising THM-0071 only. Recommendation: THM-0135 into THM-0074's `depends_on` and THM-0136 into THM-0075's. This moves both roots' dependency claims, so decide it before the records are written.
4. **NP-290 and the outbound public Web PKI premise (B4).** THM-0090 tacitly relies on outbound TLS authenticating the named server, and no assumption covers that. Either add a public-Web-PKI sibling of ASM-0070, or leave NP-290 unratified.
5. **ASM-0090/0091 liveness split (O3), optional.** A separate liveness unit decouples them from the two safety theorems.
6. **ADR-070 O4 (D1 scope under the required posture) and O5 (signing window vs the G2 wait).** See `docs/architecture/audit-commitment.md` and the B3/B6 sections. No B3 theorem claims the window covers G2.

Notes recorded for the permanent evidence: THM-0128 (the Lean model is predicted byte-identical, which only the extraction confirms), THM-0111, THM-0045, THM-0063, THM-0069, THM-0070, THM-0089, THM-0109 and THM-0074, each in its batch section below.

---

# B1a — formal core/http_profile units: proof-dependency and whole-crate source movement

Candidate `exec/1201-pre-assurance @ 6127939a`, baseline `origin/main @ 8262c5fa` (133/133 REVIEWED).
Read-only. Proposed verdicts only; no record written.

## The change behind this batch

All ten theorems are stale for ONE cause: four files of `mcp-re-core` changed, and `mcp-re-core`
is measured whole by every formal unit that touches it. Per `_fingerprint.py:770-787` a formal
(V1/V2) unit's `source_inputs` is every `.rs` file of its own crate (`_formal_sources`), and its
`proof_dependencies` is the whole source of the first-party crates in its dependency closure
(`_crate_sources(formal_closure)`). So:

- `core.time_rfc3339` (V1) and `core.time_civil_from_days` (V2) live in `mcp-re-core`:
  **source_inputs** moved.
- `http_profile.freshness_window`, `.admission_currency`, `.artifact_typing`,
  `.continuation_unbypassability`, `.continuation_binding` (all V1) live in
  `mcp-re-http-profile`, which depends on `mcp-re-core`: **proof_dependencies** moved.
  `mcp-re-http-profile` itself is byte-identical over `8262c5fa..6127939a` (`git diff --stat`
  empty), which is why their `source_inputs` did not move.

No other component moved for any of the ten: `proved_symbols`, `extracted_symbols`,
`lean_theorems`, `test_selection`, `test_sources`, `mutation_probes` and the theorem
claim/dependency digests are unchanged (`review-cand.json`; every specification axis is
REVIEWED).

The `mcp-re-core` diff (78+/15-) is exactly:

| file | change | origin |
|---|---|---|
| `src/error.rs` | new variant `McpReError::AuditCommitmentUnavailable` (`:133`), its wire code `mcp-re.audit_commitment_unavailable` (`:328`), an `ALL_ERRORS` entry (`:410`), a frozen-code test case | f900b805 (#1204, D12); doc wording bc8cde82 (#1220) |
| `src/audit/reason_label.rs` | one label arm for the new variant (`:48`) | f900b805 (#1204) |
| `src/audit.rs` | two new `event_type` constants `EXECUTION_INTENT`, `AUDIT_ACCOUNTING` (`:72-77`), two new allowlists `EXECUTION_EVENT_TYPES`, `ACCOUNTING_EVENT_TYPES` (`:107-112`), doc text on `REQUEST_ACCEPTED`/`Decision::Accepted` | f900b805 (#1204, D1), e2f097a6 (#1206, Q3), bc8cde82 (#1220) |
| `src/audit/half.rs` | new `AuditHalf::Execution` and its arm (`:30`, `:59`); test loops over the two new allowlists | f900b805, e2f097a6 |

**What the provers see.** The `verus!` code of `mcp-re-core` is `time/mod.rs`, `verus_proofs.rs`
and `verus_std_specs.rs` — none changed. The only Verus contact with the changed files is
`verus_std_specs.rs:23`, `#[verifier::external_type_specification] pub struct
ExMcpReError(McpReError)`: McpReError is an opaque datatype to the prover, "no behavioural
claim rides on it". Adding a unit variant does not change any `ensures`: the one postcondition
over a `Result<_, McpReError>` (`parse_rfc3339_utc`, `time/mod.rs:148-151`) speaks only of the
`Ok` value, and every error the function returns is `ExpiredRequest` (unchanged). The
`verus!` code of `mcp-re-http-profile` (`evidence/prover_model.rs`, `artifact/thumbprint.rs`,
`policy/bounds.rs`, `block/artifact_binding/reads.rs`, `verus_std_specs.rs`) names no
`McpReError` and nothing from `mcp_re_core::audit`; its only core items are `b64url_encode`,
`MaxClockSkew` and `VerificationKey` (`verus_std_specs.rs:74`), none of which changed.

**Proved / extracted symbols changed: none.** Every changed line is outside every
`proved_symbols` / `extracted_symbols` body and outside every `verus!` block.

**Classification.** Cause: **dependency change** (a proof dependency / whole-crate formal source
moved) for the five http_profile units; for the two core units the unit's measured cone is the
whole crate, so the movement is in the unit's own **source_inputs** but in files that are not
part of the claimed function — still a dependency change in substance, recorded as such. Not
source movement (nothing was moved), not an implementation change in any proved symbol, not a
claim change. No pre-existing debt: all ten were REVIEWED at `8262c5fa`.

**Evidence still bears.** The evidence for all ten is a prover run (Verus for V1, Lean over
the Aeneas model for V2); it is re-established by the overnight host + extraction lanes. Nothing
in this diff removes a proved symbol, an `ensures`, or an assumption. Re-attesting these
reviews needs the prover lane to re-run on 6127939a's tree; the review itself has nothing to
re-read in the claimed code.

### Lean / Aeneas for THM-0128 (and THM-0002)

- The extracted unit's own code is unchanged: `mcp-re-core/src/time/format.rs` (`civil_from_days`,
  `:23-34`) and `time/mod.rs` have an empty diff.
- The committed model `verification/lean/generated/McpReCore.lean` (64 lines) contains exactly
  one definition, `time.format.civil_from_days`, with source anchor
  `'mcp-re-core/src/time/format.rs', lines 23:0-34:1` — unchanged lines. It names no error or
  audit type.
- So regeneration is expected to reproduce `McpReCore.lean` byte-identically, and
  `CivilFromDays.lean` (`MCPRE.Time.civil_from_days_total`) is unaffected. The regeneration
  stamp (`.verification/lean/regeneration-stamp.json`, machine-local) WILL be stale: its source
  set is the whole `mcp-re-core` closure plus `MODULE.bazel` and `bazel/crates.lock`
  (pa-lean.md), and the four core files AND `MODULE.bazel`/`bazel/crates.lock` (RustSec/TLS
  repair, 79872d83/37b522b2) changed. A stale stamp means `check-generated` cannot pass until
  regeneration runs. That is a prediction, not a result: only an extraction run establishes the
  byte-identity.

THM-0002 (`core.time_rfc3339`) is Verus, not Lean; no regeneration bears on it.

## Per-theorem verdicts

### THM-0001 — Admitted request parameters imply a current freshness window — **CLEAN**
- Cause: dependency change (proof_dependencies of `http_profile.freshness_window`). Origin: #1204 f900b805, #1206 e2f097a6, #1220 bc8cde82 (core only).
- Moved: `http_profile.freshness_window` proof_dependencies.
- Diff: none in the unit's crate. Proved symbols `check_params`, `VerifierPolicy::max_clock_skew`, `max_signature_validity` and their files (`verify/floor/params.rs`, `policy.rs`, `policy/bounds.rs`) are unchanged.
- Adversarial: could the new error variant or the new audit constants enter the freshness proof? No — the http-profile `verus!` code names neither. Could `MaxClockSkew` (core) have changed? No; only the four files above changed.
- Evidence: Verus over `mcp-re-http-profile` with core as dependency; to be re-run overnight.

### THM-0002 — RFC 3339 parsing is total and range-bounded — **CLEAN**
- Cause: dependency change within the unit's whole-crate cone (`core.time_rfc3339` source_inputs). Origin: same three commits.
- Moved: `core.time_rfc3339` source_inputs.
- Diff: `time/mod.rs`, `time/format.rs`, `verus_proofs.rs`, `verus_std_specs.rs` (the declared paths) are unchanged. The movement is `error.rs`/`audit*.rs`, outside the proof.
- Adversarial: the return type `Result<i64, McpReError>` gained a possible variant. The postcondition `out matches Ok(v) ==> -62167219200 <= v && v <= 253402300799` (`time/mod.rs:148-151`) does not quantify over the error type, and the body returns only `ExpiredRequest`. Totality is unaffected.
- Evidence: Verus lane; re-run overnight.

### THM-0003 — Admission verdict integrity — **CLEAN**
- Cause: dependency change. Origin: as above.
- Moved: `http_profile.admission_currency` proof_dependencies.
- Diff: `admission/*`, `admission_policy.rs`, `authoritative_admission/mod.rs` unchanged; proved `authenticate_admission`, `check_admission` unchanged.
- Adversarial: no admission code consumes `McpReError` or the audit vocabulary inside a `verus!` block.

### THM-0004 — Admission anti-rollback — **CLEAN**
- Same unit, same cause and origin as THM-0003. Anti-rollback is a property of `check_admission`, unchanged.

### THM-0005 — A degraded admission is a CANDIDATE, and requires deployment opt-in — **CLEAN**
- Same unit, cause and origin as THM-0003. The candidate/opt-in logic is in unchanged `admission/` files.

### THM-0006 — Presenter binding — **CLEAN**
- Same unit, cause and origin as THM-0003. `authenticate_admission` unchanged.

### THM-0007 — A typed artifact verifier admits only its own type — **CLEAN**
- Cause: dependency change. Origin: as above.
- Moved: `http_profile.artifact_typing` proof_dependencies.
- Diff: `artifact.rs`, `artifact/thumbprint.rs`, `block/artifact_binding/*` unchanged. The only core item the proof reaches is `b64url_encode` (`thumbprint.rs:10`), unchanged.

### THM-0009 — A presented continuation cannot bypass verification — **CLEAN**
- Cause: dependency change. Origin: as above.
- Moved: `http_profile.continuation_unbypassability` proof_dependencies.
- Diff: `dispatch.rs`, `dispatch/*`, `verify/*/request.rs`, `verified_request/*` unchanged; proved `prepare_http_dispatch` unchanged. `dispatch.rs:89` calls `McpReError::from(self).wire_code()` outside the proof; the new variant changes neither the `From` mapping (http-profile unchanged) nor anything proved.
- depends_on THM-0010 (also CLEAN here); its claim digest did not move.

### THM-0010 — Continuation handles match their retained evidence in slot — **CLEAN**
- Cause: dependency change. Origin: as above.
- Moved: `http_profile.continuation_binding` proof_dependencies.
- Diff: `block.rs`, `evidence/digest.rs`, `evidence/role.rs`, `ids.rs` unchanged; proved `HttpContinuation::verify`, `RequestEvidenceDigest::same_handle` unchanged.

### THM-0128 — The civil-date conversion is total on the domain its caller can supply — **CLEAN-NOTE**
- Cause: dependency change within the unit's whole-crate cone (`core.time_civil_from_days` source_inputs). Origin: same three commits.
- Moved: `core.time_civil_from_days` source_inputs.
- Diff: `time/format.rs` (`civil_from_days`, `:23-34`) and `time/mod.rs` unchanged. Extracted symbol, Lean theorem `MCPRE.Time.civil_from_days_total` and the generated model's source anchor are unchanged.
- Adversarial: could the Aeneas model change? The model contains only `civil_from_days` (i64 → tuple), which reaches none of the changed files; expected byte-identical.
- **Note:** the claim holds, but its evidence lane cannot currently pass `check-generated` without a regeneration: the machine-local regeneration stamp is stale on `audit.rs`, `audit/half.rs`, `audit/reason_label.rs`, `error.rs` and, since the RustSec/TLS repair, on `MODULE.bazel` and `bazel/crates.lock`. Byte-identity of `McpReCore.lean` is predicted, not measured; the overnight extraction phase must regenerate and show `git status verification/lean/generated` clean. If the model did change, this verdict must be re-read.

---

# B1b — re-review: http_profile result units, Core verdict/audit vocabulary (THM-0014–0022, THM-0111, THM-0122)

Candidate `exec/1201-pre-assurance @ 6127939a`; baseline `origin/main @ 8262c5fa` (133/133 REVIEWED).
Read-only. No claim edited, no record written. Verdicts are PROPOSED for the owner.

## The change behind this batch

`git diff --stat 8262c5fa..6127939a` over every path of every moved unit in this batch
(all of `mcp-re-http-profile/`, `mcp-re-core/`, `mcp-re-conformance/`, `mcp-re-test-paths/`,
`mcp-re-client-core/`, the proxy's `http_profile_dispatch*`, and `rust-targets.json`) touches
exactly six files. **No file under `mcp-re-http-profile/` changed.**

| file | origin | what changed |
|---|---|---|
| `mcp-re-core/src/error.rs` | f900b805 (#1204, D12), bc8cde82 (#1220, doc) | one new variant `McpReError::AuditCommitmentUnavailable` (`:133`), its `wire_code` arm `"mcp-re.audit_commitment_unavailable"` (`:328`), its `ALL_ERRORS` entry (`:410`), its wire-string test (`:488`). No existing variant, token or arm changed. `Display` is `wire_code()` (`:370-374`), so it renders identically. |
| `mcp-re-core/src/audit/reason_label.rs` | f900b805 | one exhaustive-match arm for the new variant, label "Required audit commitment unavailable" (`:48`). No wildcard arm. |
| `mcp-re-core/src/audit.rs` | f900b805 (D1), e2f097a6 (#1206, Q3), bc8cde82 (doc) | two new `event_type` constants `EXECUTION_INTENT` (`:74`), `AUDIT_ACCOUNTING` (`:77`); two new one-item allowlists `EXECUTION_EVENT_TYPES` (`:107`), `ACCOUNTING_EVENT_TYPES` (`:112`); doc text. `SUCCESS_EVENT_TYPES`, `REJECTION_EVENT_TYPES`, `KEY_LIFECYCLE_EVENT_TYPES`, `AuditEvent`'s fields and its six constructors are byte-unchanged. No new constructor; none takes a string. |
| `mcp-re-core/src/audit/half.rs` | f900b805, e2f097a6 | new `AuditHalf::Execution`; `EXECUTION_INTENT => Execution` (`:59`); accounting falls to `NonExchange`, and the catch-all test now walks all five allowlists and pins accounting to `NonExchange` deliberately. |
| `mcp-re-conformance/tests/audit_vocabulary_guard_test.rs` | f900b805, e2f097a6 | two new tests pinning the execution and accounting sets to EXACTLY one item each and disjoint from every other set; both new sets chained into the token-membership and wire-code-collision checks. Additions only: no test, assertion or expected set removed or loosened. |
| `verification/generated/rust-targets.json` | 6fd82e55, 70a4651f, f900b805, ab46131a, e2f097a6, 37b522b2 | no target added or removed; `//mcp-re-proxy` library/test targets' `srcs` 440 → 495 (new modules), two async test targets' `srcs` 21 → 23, `features` +1 on four targets (`audit_commitment_reference`). No crate-membership change. |

The new verdict token is produced only by the proxy commitment gates
(`audit_commitment/intent.rs:99,111,155`, `outcome.rs:78`, `posture.rs:294`) by NAMING the
variant; no http-profile, client-core or conformance production code constructs it, and no
other production file spells it.

**Why the http_profile units moved.** Every `http_profile.*_result`, `*_shared_facts` and
`delegated_credential_chain` unit lists `mcp-re-core/src/error.rs` in its `paths`, so the new
variant moves their `source_inputs`. `http_profile.freshness_window` is class V1 (Verus); its
`proof_dependencies` digests the source of the first-party crates the prover compiles beside
`mcp-re-http-profile`, i.e. `mcp-re-core`, so all four Core edits move it
(`tools/verification/_fingerprint.py:779-787`). Its proved symbols (`check_params`,
`VerifierPolicy::max_clock_skew`, `max_signature_validity`) are unchanged and use
`HttpProfileError`, not `McpReError` (`verify/floor/params.rs:93-138`); none of them, nor any
http-profile production code, references `ALL_ERRORS`, `AuditHalf`, any `*_EVENT_TYPES` or
`reason_label`. The only http-profile reach into the audit vocabulary is a test that pins
`KEY_LIFECYCLE_EVENT_TYPES` (`custody/lifecycle_event.rs:112-126`), which is unchanged.
The http-profile → Core projection (`error/core_projection.rs`) is unchanged and exhaustive; a
new TARGET variant cannot change which Core verdict any carrier failure maps to.

No `mutation_probes`, `test_selection` or `proved_symbols` component moved for any http_profile
unit in this batch.

**Evidence still owed (not a claim defect).** `freshness_window`'s Verus evidence was measured
over the old Core source; the overnight Verus lane re-verifies `check_params` over the new Core
closure. The review verdict below says the proposition holds; it does not substitute for that
run.

## Per-theorem verdicts

### THM-0014 — A successful request-floor verification establishes the cryptographic floor — **CLEAN**
- Cause: implementation change in a shared declared input (Core `error.rs`, additive; the unit's behaviour is unchanged) + dependency change (`freshness_window` proof dependencies).
- Origin: #1204 f900b805 (D12), #1206 e2f097a6 (Q3), #1220 bc8cde82 (docs).
- Moved: `http_profile.request_floor_result` source_inputs; `http_profile.freshness_window` proof_dependencies.
- Diff: only the new `AuditCommitmentUnavailable` variant in `error.rs`. The floor verifier neither produces nor matches it. `verify/floor/signature.rs:56` still produces `InvalidSignature`.
- Adversarial: can the new variant change which floor failure is reported? No; the floor reports `HttpProfileError`, and the projection is unchanged. Can it change the Verus freshness premise? No; the proved function's types and body are unchanged.
- Evidence: test selection unchanged; Verus re-run owed overnight.

### THM-0015 — A successful full-profile request verification establishes audience and artifact binding — **CLEAN**
- Cause: implementation change in a shared declared input (Core `error.rs`, additive).
- Origin: #1204 f900b805, #1220 bc8cde82.
- Moved: `http_profile.request_full_result` source_inputs.
- Diff: `error.rs` only. Audience, artifact, PDP-binding and `mcp_transport` sources are unchanged.
- Adversarial: no full-request path constructs or matches the new variant.

### THM-0016 — A successful bound response-floor verification establishes trust-seam authorization of the signer — **CLEAN**
- Cause: shared-input implementation change + dependency change (freshness proof dependencies).
- Origin: #1204 f900b805, #1206 e2f097a6, #1220 bc8cde82.
- Moved: `http_profile.bound_response_seam_result` source_inputs; `freshness_window` proof_dependencies.
- Diff: `error.rs` only in the unit; Core audit edits in the proof closure only.
- Adversarial: the trust-seam (`verify/floor/trust_slot.rs`, `verify/floor/response.rs`) is unchanged.

### THM-0017 — A successful unbound response-floor verification establishes trust-seam authorization and no request binding — **CLEAN**
- Cause, origin, moved, diff and adversarial checks as THM-0016, with `unbound_response_seam_result`.
- `verified_response/unbound.rs` is unchanged.

### THM-0018 — A successful full bound response verification establishes block agreement with the expected handle — **CLEAN**
- Cause: shared-input implementation change (Core `error.rs`).
- Origin: #1204 f900b805, #1220 bc8cde82.
- Moved: `http_profile.bound_response_full_result` source_inputs.
- Diff: `error.rs` only. `verify/full/response.rs` and `verified_response/bound.rs` are unchanged.

### THM-0019 — A successful delegated bound response verification establishes an accepted credential chain — **CLEAN**
- Cause: shared-input implementation change (Core `error.rs`) in both moved units.
- Origin: #1204 f900b805, #1220 bc8cde82.
- Moved: `http_profile.delegated_bound_result`, `http_profile.delegated_credential_chain` source_inputs.
- Diff: `error.rs` only. The `delegation/*` and JOSE sources, `credential_chain.rs`, `expectations.rs` and `delegated_bound.rs` are unchanged.
- Adversarial: chain acceptance still produces only the delegation verdicts it did; none is the new variant.

### THM-0020 — A successful delegated unbound response verification establishes a chain and never a binding — **CLEAN**
- Cause, origin and diff as THM-0019, with `delegated_unbound_result`.

### THM-0021 — A successful bound-response verification establishes the shared cryptographic and request-binding facts — **CLEAN**
- Cause: shared-input implementation change + dependency change (freshness proof dependencies).
- Origin: #1204 f900b805, #1206 e2f097a6, #1220 bc8cde82.
- Moved: `http_profile.bound_response_shared_facts` source_inputs; `freshness_window` proof_dependencies.
- Diff: `error.rs` only.
- `rejection/retry_contract.rs` is in this unit's paths and is unchanged. It names `EvidenceRetentionIndeterminate` (`:116`) specially; the new wire code takes the generic path, so its retry contract follows the exchange disposition. This is consistent with D12's "token states nothing about execution" (`error.rs:129-131`). The proxy-side disposition is THM-0081's batch.

### THM-0022 — A successful unbound-response verification establishes the shared facts and no request binding at all — **CLEAN**
- Cause, origin and diff as THM-0021, with `unbound_response_shared_facts`.

### THM-0111 — Two vocabularies decide what an mcp-re.* verdict token says, and every other producer names a verdict rather than spelling one — **CLEAN-NOTE**
- Cause: implementation change. Core `error.rs` gained one verdict token in its own frozen file. The guard test gained tests. `rust-targets.json` grew the proxy's scanned source list.
- Origin: #1204 f900b805 (D12); #1206 e2f097a6; RustSec/TLS 37b522b2 (rust-targets.json only).
- Moved: `conformance.carrier_minting_absence` source_inputs + test_sources; `conformance.verdict_vocabulary_scope` source_inputs; `core.verification_taxonomy` source_inputs.
- **Proposition holds.**
  - The new token `mcp-re.audit_commitment_unavailable` is spelled in `mcp-re-core/src/error.rs` only, one of the two permitted files.
  - Every proxy producer names the variant (`Refusal::new(McpReError::AuditCommitmentUnavailable, …)`).
  - The workspace scan now covers 495 proxy sources. `rust-targets.json` added no crate and removed none; crate membership still comes from the manifest.
  - `ALL_ERRORS` gained the variant, and `wire_code`/`Display` render it once. The `core.verification_taxonomy` tests `all_errors_is_duplicate_free` and `all_wire_codes_is_exhaustive` quantify over it.
  - The carrier projections (`http-profile`, proxy dispatch, client-core) are unchanged and have no wildcard arm.
  - The dotted literals `mcp-re.execution.intent` and `mcp-re.audit.accounting` appear in proxy production (`serving_capabilities/audit_posture.rs:142,148,232,236`, `audit_record/accounting.rs:6` doc). They are audit event types, outside this theorem's verdict-token definition. The `canonical.rs:703,713` comparisons sit below that file's `#[cfg(test)]` (`:113`).
- **Note.** The statement says the dotted vocabulary's "success, rejection and key-lifecycle sets are pinned to exact allowlists". Two more sets now exist and are pinned the same way (execution, accounting). The sentence is still true, only incomplete. If the owner wants it complete, add "and the execution and accounting sets (ADR-MCPRE-070 D1, Q3)"; that would move THM-0111's claim. No change is needed for truth.
- Evidence: the guard test kept every prior test and gained 2. The anti-vacuity "≥ fifteen frozen tokens" floor is unchanged and still met.

### THM-0122 — A security record says what a Core verdict says, and its display text is never a verdict — **DISCREPANCY (claim text stale against the authorized vocabulary extension; proposition otherwise holds)**
- Cause: implementation change. The audit vocabulary gained two categories under D1 and Q3. Claim text not updated: a semantic claim change is owed.
- Origin: #1204 f900b805 (D1 `mcp-re.execution.intent`), #1206 e2f097a6 (Q3 `mcp-re.audit.accounting`), #1220 bc8cde82 (docs).
- Moved: `core.audit_vocabulary` source_inputs; `conformance.audit_vocabulary_drift` source_inputs + test_selection + test_sources.
- **Defect.** The statement says: "The net-new surface is exactly five events the error taxonomy cannot express: two successes … and three delegated-key lifecycle events." At 6127939a the pinned net-new surface is seven:
  - two successes and three lifecycle events, unchanged;
  - `EXECUTION_EVENT_TYPES = [mcp-re.execution.intent]` (`audit.rs:107`);
  - `ACCOUNTING_EVENT_TYPES = [mcp-re.audit.accounting]` (`audit.rs:112`).
  
  The guard pins all four sets exactly. "Exactly five" is false at the candidate. The extension is authorized (D1; Q3, which supersedes "exactly two changes"), so the code is right and the claim is stale.
- **What still holds, verified.**
  - Every rejection reason is a frozen `wire_code()` token BY TYPE. `AuditEvent` is unchanged: its fields are private, its six constructors are unchanged, and none takes a string.
  - Neither new event has a reason:
    - the intent is `[event, actor, at]` (`mcp-re-proxy/src/audit_record/intent.rs:42-47`);
    - the accounting record is 14 fields of counts, interval and a coverage token (`accounting.rs:82-99`).
  - No `authorization_hash_mismatch` reason exists.
  - Every new verdict has its own label. `reason_label` stays exhaustive with no wildcard. `every_verdict_has_its_own_sentence` and `a_label_is_never_a_wire_token` iterate `ALL_ERRORS`, which includes the new variant.
  - The two success events and the three lifecycle events are byte-unchanged. Only the `REQUEST_ACCEPTED` doc comment was sharpened from "passed verification" to "admitted …; not executed" (`audit.rs:52-53`), which matches D1's "request.accepted continues to mean admission".
- **Proposed fix (claim text; owner specification review).** Replace the second paragraph's first sentence with:

  > The net-new surface is exactly seven events the error taxonomy cannot express: two successes (`mcp-re.request.accepted`, `mcp-re.response.signed`), three delegated-key lifecycle events, the execution intent (`mcp-re.execution.intent`, ADR-MCPRE-070 D1, vocabulary revision 2) and the bounded accounting record (`mcp-re.audit.accounting`, ADR-MCPRE-070 D2/Q3, revision 3); neither of the last two carries a reason.

  This moves THM-0122's claim. It is a root of no theorem, and no theorem `depends_on` it.
- **Drafting notes (no fingerprint effect: unit descriptions are not fingerprinted).**
  - `conformance.audit_vocabulary_drift`'s description says the audit layer's tokens are "one of the seven fixed event types". It should be nine (four verdict, three lifecycle, one execution, one accounting).
  - `core.audit_vocabulary`'s description should name the execution and accounting sets beside the success and lifecycle sets.
  - The test name `half::tests::the_three_halves_are_distinguishable` now checks four halves. Renaming it moves `core.audit_vocabulary`'s test selection.
  - The exact one-item pins for the two new sets live only in the conformance guard. `core.audit_vocabulary`'s own Core tests pin the success and lifecycle sets but not these two; only the half-assignment test walks them. That is one evidence route where the older sets have two. It is a coverage note, not a gap in the claim.
- Evidence: test selection +2 (`execution_event_set_is_exactly_the_one_item_allowlist`, `accounting_event_set_is_exactly_the_one_item_allowlist`), both registered on `conformance.audit_vocabulary_drift`. No test was removed or weakened.

---

# B2: exchange, dispatch and retention core (epic #1201). Re-review at 6127939a

Baseline: 8262c5fa, where every theorem below was REVIEWED. This is a read-only review: no record was written and no claim was edited.

Theorem fingerprints at 6127939a (from `review --fingerprint`):

| theorem | fingerprint |
|---|---|
| THM-0101 | `sha256:4dc7e4a70e82dc5fd1ba9638b5d4ce1f2582494e736d3f700d9ba6e6f202a96c` |
| THM-0074 | `sha256:9e35e992b57f53de19ca6d9c2d400a41bbb4e06ee404c408fa26e28e8615b20e` |
| THM-0043 | `sha256:34353106…` |
| THM-0044 | `sha256:a2c4aa58…` |
| THM-0045 | `sha256:a3677e05…` |
| THM-0051 | `sha256:cc371a5d…` |
| THM-0052 | `sha256:597274da…` |
| THM-0078 | `sha256:cff60d49…` |
| THM-0081 | `sha256:bf723ba2…` |
| THM-0088 | `sha256:4cd39138…` |

Claims and dependencies are unchanged for every theorem except two:
- THM-0101's own claim moved (6127939a).
- THM-0074's `theorem_dependencies` moved. The only differing entry is THM-0101's digest; THM-0074's own claim is byte-identical to its record.

## What changed behind this batch

| origin | change |
|---|---|
| #1204 (f900b805), G1 | `assemble_ready` (`http_profile_serve/dispatch_commitment.rs:120-165`) now does four things. It asks the signing window over `completion_bound().after(pre_dispatch_wait())`. It commits the execution intent through `self.audit.intent(..)` after the retention reserve and before `ReadyForDispatch::new`. It refuses through `refuse_accepted`; dropping `accepted` rescinds the reservation, and dropping `prepared` returns plane capacity. `ReadyForDispatch` and `DispatchedExchange` carry a fourth by-value field, `IntentDisposition` (`request_stages.rs:92-160`), a closed two-arm sum (`request_stages/intent_disposition.rs`). |
| #1204, refactor | `PreDispatchRetention` and `RetentionDisposition` moved verbatim to `request_stages/retention_disposition.rs`, with their test `the_retention_obligation_has_exactly_two_cases` (`:88`). |
| #1205 (ab46131a), G2 / Q2 / D4 | One success exit, `reply_assembly/success_exit.rs:35-78`, runs in this order: outcome commit (G2), then `retain_accepted`, then offer the record, then `progress.publish`, then `served`. The bodied reply (`accepted.rs`) and the 202 (`notification.rs`) both leave through it. `handle`'s post-dispatch tail moved to `reply_assembly/dispatched.rs`. |
| #1220 (bc8cde82, a676dfd5) | The 202's terminal is the stage-owned carrier `Established<NotificationDelivered>`, built only by `InnerPlane::observe_acknowledgement`; the struct's field is private to `inner_plane` (`inner_plane.rs`). `ServedSuccess<D>::Acknowledged(Established<D>)` is decided by `may_publish` before signing and entered by `publish` after G2 and retention. `establish_terminal` is deleted. |
| 7b6ab1a8 | Doc wording only: `exchange_state.rs:702-703`, `http_profile_serve/mod.rs:421-423`. |
| 6127939a | THM-0101 text (see below). |

Not touched: `transition`, the `ExchangeEvent` set, `retry_semantics`, everything under `transparency/`, `authorization/dispatch.rs` and `signing_window.rs`. The only `exchange_state.rs` hunks are at `:349-375` (ServedSuccess), `:538-559` (Established) and `:699-729` (establish, may_publish, publish), plus tests.

### Test selection: the shared async harness

`integration_async_test` now compiles with `crate_features = ["async_serve", "audit_commitment_reference"]` (`mcp-re-proxy/BUILD.bazel:1372`). Its `main.rs` gained `intent_before_dispatch_test` and `outcome_before_success_test`, and `integration/main.rs` gained `prepared_dispatch_source_test`.

That feature only ADDS items. Every use is `#[cfg(any(test, feature = "audit_commitment_reference"))]`: `dispatch_commitment.rs:183`, `audit_commitment/{mod,providers,provider_id}.rs` and `lib.rs:330`. No existing control changes behaviour under it, and `scripts/fixture_feature_gate.py` keeps it out of deployable flavors. This is what moves `test_selection` / `test_sources` for units whose controls live in those targets, such as `proxy.pdp_decision_relation`, whose `pdp_authorization_serving_test.rs` is byte-identical.

### Mutation probes in these units

Three probes changed. Each was re-anchored to the new code, and none was weakened.

| probe | change | killer (present) |
|---|---|---|
| M160 | anchor `covers(window, prepared.completion_bound())` → `covers(&window, completion)`; weakening `if false {` unchanged | `delegated_serving_test.rs` |
| M92 | anchor `may_publish(success)` → `may_publish(&success)` | `accepted.rs::the_publication_decision_precedes_retention_and_the_response_signed_record` |
| M93 | anchor and weakening `establish_terminal(acknowledged)` → `may_publish(&acknowledged)` | `notification.rs::the_terminal_is_decided_before_the_202_is_minted` |

New controls:
- `intent_before_dispatch_test.rs::an_intent_refusal_leaves_no_pending_marker` (M610);
- `exchange_transition_ownership_test.rs::the_202_terminal_is_entered_through_its_stage_s_carrier`;
- `prepared_dispatch_source_test.rs`: `prepared_dispatch_is_transmitted_only_by_the_ready_state`, plus its scanner self-test.

Removed tests in these units: none. Two moved or restated:
- `the_retention_obligation_has_exactly_two_cases` moved to `retention_disposition.rs:88`.
- The `establish_terminal` unit tests are restated over `prospective_refusal` / `may_publish` with the same assertions, including the latch on the live machine.

The order test in `accepted.rs` now asserts that `decision < exit`. The order inside the exit is asserted in `success_exit.rs` tests, at `:112` and `:145`. The second of those now also scans `dispatched.rs`, at 7b6ab1a8.

---

### THM-0043 — The exchange relation is decided everywhere and the execution threshold partitions it — **CLEAN**
- **Cause:** source movement.
- **Origin:** #1205, #1220.
- **Moved:** `proxy.exchange_relation` `source_inputs` (`exchange_state.rs`).
- **The diff:** it touches the publication API only (ServedSuccess, Established, may_publish, publish). It does not touch `transition`, the event set, the terminal set or the latch.
- **Adversarial check:** `publish` still drives every event through `advance`, which checks the relation and latches. The deleted `establish_terminal` was `prospective_refusal` plus `establish`; `may_publish` plus `publish` keep both halves, from one tail.

### THM-0044 — An exchange's retry consequence never under-reports what may have happened — **CLEAN**
- **Cause:** source movement.
- **Origin:** #1205, #1220.
- **Moved:** `proxy.exchange_retry_consequence` `source_inputs` (same file).
- **The diff:** `retry_semantics` and the Consumed latch are untouched.
- **Adversarial check:** the 202 terminal is now entered later, at publish rather than at observation. Before publish, the state is `Dispatched`, which already reports `NotRetrySafe`; the test `a_refused_202_is_served_from_a_non_terminal_state` asserts this at `exchange_state.rs:2025`. Entering later cannot move the consequence backward.

### THM-0045 — The backend is reached only by consuming a fully assembled pre-dispatch commitment — **CLEAN-NOTE**
- **Cause:** implementation change.
- **Origin:** #1204 (G1).
- **Moved:** `proxy.dispatch_commitment` (`mutation_probes`, `source_inputs`, `test_selection`, `test_sources`) and `proxy.retention_commitment` (same four).
- **Still true:** `ReadyForDispatch` takes `PreparedInnerDispatch`, `SigningWindow` and `RetentionDisposition` by value. `dispatch` consumes the ready state and the capability, and yields `DispatchedExchange`. The window is snapshotted before the backend runs and is now asked over a longer bound (`.after(pre_dispatch_wait())`, checked arithmetic, `completion_bound.rs` + `completion_bound_after_is_checked`), which is strictly more conservative.
- **NOTE:** the statement's list of prerequisites ("each pre-dispatch prerequisite by value: a, b, c") is now incomplete. `ReadyForDispatch` also takes an `IntentDisposition` by value. The omission under-states rather than over-states, and the intent prerequisite is THM-0135's claim (D10: separate theorems for G1 and G2). No edit is proposed; the owner should know the enumeration is no longer exhaustive.

### THM-0051 — The pipeline holds, at dispatch, the verification product of this very exchange — **CLEAN**
- **Cause:** implementation change in a supporting unit, not touching verified-product provenance.
- **Origin:** #1204.
- **Moved:** `proxy.dispatch_commitment` (all four).
- **The diff:** the verified product is not touched. The intent is built from `acc.exchange().actor_id` and `.now`, not from the verified request. `ReadyForDispatch::new` moved from `mod.rs` into `assemble_ready`. `scripts/serving_product_provenance_gate.py`, the theorem's declared mechanism, passes at 7b6ab1a8 and later (CI rust-job replay, 50/50 steps).

### THM-0052 — A dispatched body was released by the decision a configured policy produced — **CLEAN**
- **Cause:** collateral test-configuration change.
- **Origin:** #1204, #1205.
- **Moved:** `proxy.dispatch_commitment` (all four) and `proxy.pdp_decision_relation` (`test_selection`, `test_sources` only).
- **The diff:** `authorization/` has no source diff. The PDP serving tests are byte-identical; the movement is the async target's added test-only feature and two new modules in its crate (see the test-selection section above). `release` is still called once, and `scripts/authorization_provenance_gate.py` clauses 4, 7 and 10 pass.

### THM-0074 — No unearned dispatch (root R1) — **CLEAN-NOTE**
- **Cause:** dependency change (THM-0101's claim text), plus an implementation change in `proxy.dispatch_commitment` (#1204) and source movement in `proxy.exchange_relation`.
- **Origin:** 6127939a, #1204.
- **What moved:** `theorem_dependencies` moved ONLY because THM-0101's claim digest did. THM-0074's own claim is byte-identical to its record.
- **Own proposition:** unaffected. Every pre-dispatch obligation it already quantified over is established before the dispatch line exactly as before. `assemble_ready` keeps the same order (decision, prepare, window, reserve), the crossing is still recorded last, and the new G1 step sits between reserve and crossing and can only refuse.
- **NOTE (owner question):** under `--audit-commitment required`, a committed intent is a pre-dispatch obligation the validated deployment selected. R1's antecedent ("every pre-dispatch security obligation selected by the validated deployment") arguably covers it, but THM-0135 is in no root's closure. The implication is not falsified, because G1 IS established before dispatch (THM-0135); R1's closure just does not witness it.
- **Proposal:** decide, before THM-0074's record is written, either to add `THM-0135` to THM-0074's `depends_on`, or to record that the audit-commitment obligation is outside R1's "security obligation" set (D10 placed G1 and G2 in separate theorems). Adding the edge now costs nothing, since THM-0074 is being re-reviewed anyway; adding it later stales R1 again. Recommendation: add it, together with THM-0135's ratification.
- **Mechanism note:** THM-0074 cannot take a claim-correction record. Its nine historical records (`verification/claim-corrections/THM-0074-*.json`) are off the chain from its reviewed fingerprint `ff20bb85…`, so `_claim_corrections.chain()` reports dead rows, and `claim_surface_gate.py` FAILs at 6127939a ("chain ends at ff20bb850a2e5eef and the tree is at 9e35e992b57f53de"). Only an owner specification-review record at `sha256:9e35e992b57f53de19ca6d9c2d400a41bbb4e06ee404c408fa26e28e8615b20e` clears it.

### THM-0078 — Refusal is terminal, and no refusal-side effect reads as success (root) — **CLEAN**
- **Cause:** source movement plus implementation change.
- **Origin:** #1205, #1220.
- **Moved:** `proxy.exchange_relation` and `proxy.pre_dispatch_refusal_precedence` (`source_inputs`: `inner_plane.rs`, the `NotificationDelivered` carrier).
- **New refusal arms:**
  - G1 refusal: `refuse_accepted` from the machine before the crossing, with the disposition derived by `Self::disposition(progress, ..)` (NothingExecuted, or ApprovalSpentNothingExecuted where an approval was spent).
  - G2 refusal and retention failure: `refuse_retained` after dispatch, `PossiblyExecuted`.
  - 202 signing failure: `response_rejection`, disposition from the machine at `Dispatched`.
- None falls through to a success. On each, the 202 terminal is never entered, because `publish` is not reached.
- **Retention:** a G1 refusal rescinds the reservation, so no `.pending` marker reads as a crossing (`an_intent_refusal_leaves_no_pending_marker`).

### THM-0081 — Every production refusal is inside the exchange lifecycle — **CLEAN**
- **Cause:** implementation change.
- **Origin:** #1204, #1205, #1220.
- **Moved:** `proxy.refusal_site_totality` (`source_inputs` + `test_sources`: the `http_profile_serve/**` glob and the shared integration harness).
- **The diff:** every new exit (G1, G2, retention-after-G2, 202 signing) is exchange-owned and minted through `refuse_accepted`, `refuse_retained` or `response_rejection`, from a stage-named `Refusal`. `served(` appears once in production, in `success_exit.rs`, and nowhere else in the reply region (`success_exit_is_the_only_success_served_call`, now also over `dispatched.rs`). The `audit` field became `AuditPosture`; call sites pass `self.audit.observer()`, which is mechanical. The four pre-exchange replies are unchanged.

### THM-0088 — A retention artefact reads as a crossing only for an exchange that crossed — **CLEAN**
- **Cause:** implementation change in the serving half of the unit; the store half is untouched.
- **Origin:** #1204, #1205.
- **Moved:** `proxy.retention_commitment` (all four), from `accepted.rs` and `success_exit.rs`. `transparency/*` has no diff.
- **Adversarial checks:**
  - G1 sits after `reserve` and before `commit_to_dispatch`, and refuses by dropping the `ReservedBeforeDispatch`, which queues the withdrawal. So a G1-refused exchange leaves no `.pending` (new test, M610).
  - After dispatch, a G2 refusal makes `refuse_retained` complete retention with the REFUSAL. A failed attempt leaves the `.pending` marker, which "survives its own failure" as the claim says.
  - `.reserved` still carries the digest only.

### THM-0101 — An emitted exchange transition corresponds to the work that justifies it… — **CLEAN** (claim text corrected in 6127939a; owner specification review required at the new fingerprint)
- **Cause:** semantic claim change (symbol correction) plus implementation change.
- **Origin:** #1205 deleted `establish_terminal`; #1220 bc8cde82 and a676dfd5 restored the 202 carrier; 6127939a corrected the text.
- **Moved:** `theorem_claim`; `proxy.exchange_publication` (`mutation_probes`, `source_inputs`, `test_selection`); `proxy.exchange_transition_ownership` (`source_inputs`, `test_selection`, `test_sources`).
- **Old text:** named `establish_terminal` as the second reader of a carrier. That function does not exist at 6127939a.
- **New text claim 1:** the readers of an `Established` are `ExchangeProgress::establish` and, for the 202 carrier, `ServedSuccess::tail`, which reads the event alone. Measured: the only production field reads in `exchange_state.rs` are `:372` (`&acknowledged.event`, in `tail`) and `:705`/`:707` (`established.event`/`.value`, in `establish`). Both fields are private to the module, so no other module can read either.
- **New text claim 2:** `may_publish` checks the event before the 202 is signed (`notification.rs`: `may_publish(&acknowledged)` precedes `answer_notification`, which calls `sign_delegated_accepted_202`).
- **New text claim 3:** `publish` advances it after the outcome commitment and retention (`success_exit.rs:56-77`).
- **New text claim 4:** the product is never yielded. `NotificationDelivered` is dropped with the consumed `ServedSuccess`; it has no reader and a single private constructor in `inner_plane`.
- **Scope:** "nothing but `establish` can open one" means take its value, which is true. "Nothing but `establish` and `ServedSuccess::tail` reads one (structural)" is true. The structural part is module privacy; the exact two-reader set inside the module is source-measured, the same evidential status the reviewed text had for `establish` plus `establish_terminal`.
- **Proposition:** unchanged. The stage-owned set still includes `NotificationAcknowledged` (`the_202_terminal_is_entered_through_its_stage_s_carrier`). The assembly-owned set is still exactly three, and the success-tail clause still holds: `publish` alone advances `EvidenceRetained`, `TerminalResponseServed` and `OpenLegResponseServed`. The carrier battery (`the_carrier_has_no_reader_but_establish`: no pub field, `#[must_use]`, one method `new`, no trait impl) passes unchanged.
- **NOTE (doc wording, test-only):** the doc of `exchange_transition_ownership_test.rs::the_202_terminal_is_entered_through_its_stage_s_carrier` says "the publication that enters the terminal OPENS that carrier". Since a676dfd5, the publication reads the carrier's event and never opens its value. Suggested wording: "…the publication that enters the terminal reads that carrier's event". The edit moves only `proxy.exchange_transition_ownership` `test_sources`, which is already stale, so it is best made before the records are written.

## Summary

| theorem | verdict | cause | origin |
|---|---|---|---|
| THM-0043 | CLEAN | source movement | #1205/#1220 |
| THM-0044 | CLEAN | source movement | #1205/#1220 |
| THM-0045 | CLEAN-NOTE | implementation change | #1204 |
| THM-0051 | CLEAN | implementation change (collateral) | #1204 |
| THM-0052 | CLEAN | implementation change + test configuration | #1204/#1205 |
| THM-0074 | CLEAN-NOTE | dependency change (THM-0101) + implementation change | 6127939a/#1204 |
| THM-0078 | CLEAN | implementation change | #1205/#1220 |
| THM-0081 | CLEAN | implementation change | #1204/#1205/#1220 |
| THM-0088 | CLEAN | implementation change | #1204/#1205 |
| THM-0101 | CLEAN (claim corrected) | semantic claim change + implementation change | #1205/#1220/6127939a |

No DISCREPANCY. No claim edits are proposed except the optional THM-0074 → THM-0135 edge (owner decision).

Outside this batch: THM-0136 (G2) is likewise in no root's closure. If R1 takes THM-0135, R3 (`THM-0075`, response attribution) or the audit root (`THM-0071`) is the analogous question for THM-0136. D10 forbids expanding THM-0071, so THM-0075 is the candidate. That belongs to B6's call.

---

# B3: signing, credential provenance, trust composition (re-review at 6127939a)

Baseline `8262c5fa`, which was 133/133 REVIEWED. Candidate `6127939a` (local, `exec/1201-pre-assurance`).

- **Scope of the review.** No claim, premise or dependency text moved for any theorem here. Only supporting-unit semantic components moved.
- **Inputs read:**
  - each theorem's statement and scope;
  - `git diff 8262c5fa..6127939a` over every moved unit's `paths`;
  - the `rust-targets.json` rows behind `test_selection` and `test_sources`;
  - the shared integration harness files.
- **No proof input moved.** `proof_dependencies`, `mutation_probes`, `governing_boundaries` and `trusted_assumptions` are unchanged for every B3 unit.

## The change behind this batch

Three mechanical sources move every B3 unit, and none of them is the signing or trust code itself.

### 1. `app.rs` (e2f097a6 #1206; 6fd82e55 #1202)

Units affected: `proxy.trust_composition_root`, `proxy.serving_trust_seam` and `proxy.signing_credential_provenance`.

- **What moved where.**
  - `run`, `run_request` and `drained` moved to `app/entry.rs`, a new submodule (`app.rs:92-95`).
  - A new `run_with` there resolves `AuditPlan` from `deployment.state().audit()`, an owner projection (`app/entry.rs:33-50`).
  - `run_validated` gains an `AuditPlan` parameter and establishes the commitment immediately after `MaterializingRuntime::begin` and before any plane (`app.rs:218`).
  - The per-request sink becomes `serving_capabilities::audit_posture(config.state().audit(), audit)` (`app.rs:427-433`).
  - The teardown test now calls `record_to` (a test half change).
- **What was not touched:** no `values.<field>` read, no key-source construction, no change to `build_actor_resolver` (`app.rs:51-90`), no signing-role read and no trust-plane install.
- **Checked:** `git diff ... app.rs | grep '^+' | grep 'values\.|config()'` returns empty.

### 2. `receipt/audit_event.rs` and `receipt/mod.rs` (6fd82e55 #1202; D9)

Unit affected: `proxy.response_signing`.

- `Accepted` now holds the `ExchangeCoordinate` its `request.accepted` event produced (`audit_event.rs:34-36`, `:55`, `:75-81`).
- `response_rejection` takes it and passes it into `record_to` (`audit_event.rs:164-178`; `receipt/mod.rs:147`). The rejection-path `record_to` gains `None` (`:141`).
- This is audit-record linkage only. `signed_rejection`, the window and the emitters are unchanged.
- `signing_window.rs` is byte-identical.
- The window-opening sites are the same three production sites before and after (`receipt/artifact.rs:66-67`, `receipt/mod.rs:89`, `signing_window.rs:25`; `git grep` at both SHAs).

### 3. Test lane rows

Units affected: every unit with an integration selector (`test_selection` and/or `test_sources`).

- **`integration_test`:** gains `prepared_dispatch_source_test.rs` (f900b805 #1204).
- **`integration_async_test`:**
  - gains `intent_before_dispatch_test.rs` and `outcome_before_success_test.rs` (#1204, #1205, #1207);
  - its `crate_features` gain `audit_commitment_reference` (`BUILD.bazel:1372`).
  - That feature only adds items: the scripted reference authority and the `with_required_audit_commitment` seam, at `lib.rs:330`, `dispatch_commitment.rs:183`, `audit_commitment/mod.rs:109-154`, `providers.rs:46` and `provider_id.rs:28`.
  - Nothing selects them by default, so every pre-existing selected test runs the same best-effort posture as before.
- **Shared harness edits.** No assertion was removed or weakened. Removed lines are only:
  - helper re-parameterisations in `delegated_client_server_e2e_test.rs`: `build_server_over`, `client_proxy_over`, and `pub(super)` on `NOW`, `plain_request`, `plain_notification` and `params`;
  - the `startup_transcript` `AuditSink` parser, which now also reads `delivery` and has a new should-panic control for an unknown delivery.

### 4. `config_state/validation/mod.rs` (e2f097a6 #1206)

Unit affected: `proxy.online_ocsp_reachability`.

- A stale doc paragraph is replaced. It said the key-file check lives in `main.rs`; it now names `capability_materialization::admit_key_files`, and the posture list moves to "each machine's own column".
- The `Audit` machine's violations are appended last (`mod.rs:182`, `:352-354`).
- `extend` only adds violations, so no earlier clause can be suppressed.

### N3/O5: the signing window against the G2 wait

**No B3 theorem claims that the window covers the G2 wait, retention or delivery.**

- **Order.** The reply is signed under the exchange's window in `assemble_reply` (`reply_assembly/mod.rs:139`, `sign_reply(.., window)`) before `publish_success` runs G2 and retention (`success_exit.rs:43-80`). The advertised `expires` is fixed at signing.
- **G2 refusal.** A refusal after G2 goes through `refuse_retained` → `refuse_accepted` → `response_rejection`, signed under the snapshot its own exchange took (`accepted.rs:90-112`; `receipt/mod.rs:144-150`).
- **What still holds.** THM-0063 ("advertised validity ≤ the credential's bound; every window from one of the two opener sites") and THM-0075 ("signature by the materialized capability") both hold whatever the G2 delay.
- **`covers()`.** It already disclaims wall-clock completion in its own doc (`signing_window.rs:28-49`): "a bound on the DISPATCH budget and not a guarantee about wall-clock completion".
- **Consequence.** Near credential expiry, a client may receive a reply whose advertised window has already lapsed, and it refuses that reply. This is liveness and never a false acceptance, so it is O5, not a defect in THM-0062, THM-0063 or THM-0075.

## Per-theorem verdicts

### THM-0013 — No validated deployment enables online OCSP client-certificate revocation — **CLEAN**
- **Cause:** implementation change (adjacent clause) plus test-source movement. Origin: e2f097a6 (#1206) for `validation/mod.rs`; f900b805 / e2f097a6 for the integration target.
- **Moved:** `proxy.online_ocsp_reachability` `source_inputs` and `test_sources`.
- **Diff:** `config_state/validation/mod.rs` gains the `audit` field in the `MachineViolations` destructure (`:182`) and `violations.extend(audit)` last (`:352-354`); the doc block is corrected (`:121-126`). The refusal itself, `config_state/validation/residue.rs`, is byte-identical. So are `deployment_request/revocation/mod.rs` and `online_evidence.rs`.
- **Adversarial check:** can the new audit column admit `Required`? No. It only adds violations, and the residue clause is evaluated unchanged.
- **Evidence:** `test_sources` moved only through the new file and appended tests in `app_startup_characterization_test.rs`, all audit-commitment startup tests. The control `a_programmatic_config_cannot_claim_an_ocsp_check_the_serving_path_never_makes` is untouched.

### THM-0038 — The composition root consumes trust as owner projections and re-reads no trust field — **CLEAN-NOTE**
- **Cause:** source movement (the entry points moved to `app/entry.rs`) plus implementation change (audit establishment). Origin: e2f097a6 (#1206) and 6fd82e55 (#1202, test half).
- **Moved:** `proxy.trust_composition_root` `source_inputs` and `test_sources`.
- **Diff:**
  - No new `values.` read in the production half of `app.rs`.
  - The audit plumbing reads `config.state().audit()`, the classification's projection; the same expression was there before, at the old `security_audit_record` call.
  - Trust still reaches materialization only as `TrustPlan` (`app.rs` trust install unchanged).
  - `composition_raw_read_test.rs` is byte-identical, including `the_rule_would_catch_a_new_raw_read`.
- **Note for the owner:** `run` and `run_request` now live in `app/entry.rs`, which is a submodule of the composition root but not in `proxy.trust_composition_root`'s `paths`. The raw-read guard scans `MCP_RE_APP_SRC` (`app.rs`) only (`composition_raw_read_test.rs:85-113`).
  - Today `entry.rs`'s production half reads only `deployment.state().audit()`, an owner projection; no `values.` and no `config()` (grep).
  - THM-0038's scope already discloses "a helper in another file … is outside what the guard measures", so the claim is accurate. The measured file set is now narrower than the root's module, though.
  - Recommended follow-up, not required for currency: extend the guard to `app/entry.rs`, or add it to the unit's `paths`. Either moves the unit and costs one more review.

### THM-0062 — A response-signing credential exists only while a valid delegated key does — **CLEAN**
- **Cause:** test-lane movement only. Origin: the `integration_async_test` row (#1204–#1207) gained the `audit_commitment_reference` feature and two new files.
- **Moved:** `proxy.delegated_signing_credential` `test_selection` and `test_sources`.
- **Diff:** none in the unit's 11 paths; `delegated_server_signer/*`, `signing_plane/*`, `delegated_wiring.rs` and `delegated_response_signer.rs` are byte-identical.
- **Adversarial check:** the new feature only adds items and selects no new posture for `delegated_serving_test`, `delegated_production_wiring_test` or `root_key_lifecycle_test`, which are unchanged files.

### THM-0063 — A signed response never advertises validity its credential does not authorize — **CLEAN-NOTE**
- **Cause:** implementation change (audit linkage in receipt) plus test-lane movement. Origin: 6fd82e55 (#1202, D9); integration rows (#1204–#1207).
- **Moved:** `proxy.delegated_signing_credential` `test_selection` and `test_sources`; `proxy.response_signing` `source_inputs`, `test_selection` and `test_sources`.
- **Diff:** `receipt/audit_event.rs` and `receipt/mod.rs` carry the exchange coordinate into the audit record only. `signing_window.rs`, `receipt/artifact.rs` and the opener sites are unchanged.
- **Adversarial check:**
  - Is there a new `SigningWindow::over` or `signing_window::open` site? None (`git grep` at both SHAs, three production sites each).
  - Is the post-G2 refusal signed under a re-opened window? No: `refuse_accepted` uses the exchange's snapshot.
- **Note for the owner:** the N3/O5 window question above. It is liveness only and outside this claim.

### THM-0066 — The serving PEP resolves actors through the deployment's materialized trust authority — **CLEAN**
- **Cause:** source movement and implementation change elsewhere in `app.rs`, plus test-source movement. Origin: e2f097a6 (#1206) and 6fd82e55 (#1202); integration row (#1204).
- **Moved:** `proxy.serving_trust_seam` `source_inputs` and `test_sources`.
- **Diff:** `build_actor_resolver` and the single resolver construction in `run_validated` are unchanged; `request_admission.rs` is byte-identical. `serving_trust_seam_test.rs` and `revocation_serving_wiring_test.rs` are byte-identical; `test_sources` moved only through the new `prepared_dispatch_source_test.rs` in the integration crate.

### THM-0067 — The composition root re-reads no owner's security semantics from the request — **CLEAN-NOTE**
- **Cause, origin, moved components:** as THM-0038.
- **Diff:**
  - The `ORDINARY` inventory and the test are unchanged.
  - The new audit plumbing consumes the `Audit` machine's classification via `state().audit()` and the commitment owner's `AuditPlan`, not a raw field.
  - The configuration boundary's new `Audit` column is that machine's own (`validation/mod.rs:182`, `:352`).
- **Note for the owner:** the same `app/entry.rs` measurement-scope note as THM-0038.

### THM-0073 — Serving materialization refuses a deployment whose two signing roles are one key — **CLEAN**
- **Cause:** implementation change elsewhere in `app.rs` plus test-source movement. Origin: e2f097a6 (#1206); integration row (#1204).
- **Moved:** `proxy.signing_credential_provenance` `source_inputs` and `test_sources`. `proxy.signing_role_separation` did not move.
- **Diff:** the materializer call, the two eager, fallible role reads and the signing-plane install from the witness are unchanged. The new audit establishment line constructs no key source and sits after `MaterializingRuntime::begin`. `signing_plane/mod.rs` is byte-identical.
- **Evidence:** `signing_credential_provenance_test.rs` is unchanged, including `the_composition_root_reads_both_signing_roles_eagerly_and_fallibly` and `the_rules_would_catch_each_regression`. The `mutation_probes` component (incl. M432) is unchanged.

### THM-0075 — No unearned response attribution — **CLEAN**
- **Cause:** implementation change (audit linkage) plus test-lane movement. Origin: 6fd82e55 (#1202).
- **Moved:** `proxy.response_signing` `source_inputs`, `test_selection` and `test_sources`.
- **The new refusal paths of this epic:**
  - The G1 refusal `audit_commitment_unavailable` and the G2 / W5 / W5b refusals are served through `ResponseSigning` under the exchange's snapshot. They are bound to the accepted request: `Accepted` exists only after `request.accepted`.
  - The unsigned last-resort refusal is outside this claim's scope by its own text ("SECURITY-BEARING SIGNED evidence only").
- **Adversarial check:** no signing capability other than the materialized `DelegatedSigningReader` is reachable from the new code.

### THM-0082 — The serving path signs under the credential source materialization produced — **CLEAN**
- **Cause, origin, moved components:** as THM-0073.
- **Diff:** the root still opens one key source through the materializer and installs `SigningPlane::materialize(witness)`. The audit establishment takes `building.control()` and no signing input.
- **Evidence:** `the_composition_root_constructs_no_rival_key_source` is unchanged and still scans `app.rs`. `app/entry.rs` constructs no key source (production half read in full).

### THM-0099 — The production actor resolver answers its Request-slot selector from the deployment's trust document — **CLEAN**
- **Cause, origin, moved components:** as THM-0066.
- **Diff:** `build_actor_resolver` is unchanged and its call is unchanged, so the Request- and Response-slot behaviour is untouched. The premises THM-0066, THM-0097 and THM-0098 are unaffected (THM-0066 CLEAN above).

---

# B4 — boundaries, TLS and shared-harness re-review (14 theorems)

Candidate `exec/1201-pre-assurance @ 6127939a`. Baseline `origin/main @ 8262c5fa`, where all 14 were
REVIEWED. Read-only. No claim text, `supported_by` or `depends_on` of any B4 theorem moved
(`git diff 8262c5fa..6127939a -- verification/policy/theorems.toml` touches none of them). Only
supporting-unit components moved, so each review reads the semantic-input diff of its moved units.

**Result: 0 false claims, 0 discrepancies. 11 CLEAN, 3 CLEAN-NOTE (THM-0089, THM-0090,
THM-0109).**

## The two changes behind this batch

### 1. `boundary.tls_mechanism` gained a path (governing_boundaries, 7 units)

`verification/policy/trust-boundaries.toml:286-288` (commit 37b522b2, the RUSTSEC-2026-0381/-0382
repair) adds `mcp-re-proxy/src/outbound_fetch/public_roots.rs` to `boundary.tls_mechanism`'s
`paths`. `kind`, `beyond` and `max_class_without_assumption = "V0"` are byte-identical.
`_fingerprint._governing_boundaries` (`tools/verification/_fingerprint.py:729-760`) digests the
WHOLE entry (kind, beyond, cap, sorted paths) for every boundary a unit crosses, so every unit
whose paths touch `tls_listener_state/**`, `delegated_tls*` or `mcp-re-transport/src/tls_config.rs`
moved, although nothing about the boundary they cross changed for them: the same mechanism, the
same trust statement, the same cap. The other boundary change in this range,
`boundary.audit_commitment_provider` (86734cec, `:478-490`), crosses only
`audit_commitment/authority.rs` and no B4 unit.

Units moved by this alone: `proxy.credential_key_correspondence` (THM-0026),
`proxy.delegated_resolver_materialization` and `_sole_producer` (THM-0027),
`proxy.listener_state_assembly` (THM-0048), `proxy.client_certificate_posture` (THM-0054),
`proxy.epoch_bound_session_store` (THM-0103), `client.transport_server_identity` (THM-0109).
`proxy.outbound_destination` (THM-0090) is the one unit that NEWLY crosses the boundary, because
`public_roots.rs` joined its own `paths`.

Cause class for these: **dependency change** (a governing boundary entry moved). Origin: RustSec/TLS
repair 37b522b2.

### 2. The shared integration harness grew (test_sources, 9 units)

`test_sources` (`_fingerprint.py:429-452`) digests every source file of each integration-test
target a unit's selectors run. `//mcp-re-proxy:integration_test` and `:integration_kms_test` both
compile `tests/integration/**` and `tests/startup_transcript/mod.rs`, which changed:

| file | +/- | origin | content |
|---|---|---|---|
| `tests/integration/app_startup_characterization_test.rs` | +188 / -0 | e2f097a6 (#1206) | new required-posture startup tests only |
| `tests/integration/exchange_transition_ownership_test.rs` | +17 / -0 | ab46131a (#1205), bc8cde82 (#1220) | new 202-carrier source control |
| `tests/integration/main.rs` | +1 / -0 | f900b805 (#1204) | `mod prepared_dispatch_source_test;` |
| `tests/integration/prepared_dispatch_source_test.rs` | +113 / -0 | f900b805 (#1204) | new file |
| `tests/startup_transcript/mod.rs` | +65 / -12 | e2f097a6 (#1206) | `AuditSink { mode, delivery }`; `audit_posture` reads the new line strictly |

Every removed line is in the startup-transcript normalizer's audit-line arm: the old matcher
(`record = NONE` / `record = STDERR`) is replaced by `audit_posture` (`startup_transcript/mod.rs:435-460`),
which reads `STDERR, ` or `OFF (--audit-sink none), ` and a delivery of `BEST-EFFORT` or
`REQUIRED via provider …, tier …`, and panics on anything else (two new normalizer tests at
`:570-602`). It is stricter, not looser, and it parses only the audit line, which no B4 unit's
selector asserts on (`git grep AuditSink mcp-re-proxy/tests` outside the harness names only
`CollectingAuditSink`, a different type).

Every tested symbol of every B4 unit resolves at 6127939a (checked mechanically: 0 missing). The
three that live in a changed file — `a_programmatic_config_cannot_point_a_root_key_endpoint_at_a_plaintext_host`
(THM-0089), `enabling_trust_reload_changes_the_tier_line_and_the_reload_line_together` (THM-0100),
`a_config_that_skipped_the_parser_still_cannot_bypass_the_safety_guards` (THM-0102) — are in
`app_startup_characterization_test.rs`, whose diff has zero deleted lines, so their bodies are
byte-identical. No assertion was removed or weakened.

Cause class for these: **source movement (test-harness growth)** — no supporting-unit behaviour
changed and no control moved; the digest covers sibling files of the target. Origin: #1204, #1205,
#1206, #1220.

## Per-theorem verdicts

### THM-0024 — Certificate identity interpretation reads the configured field and refuses rather than falling back — **CLEAN**
- Cause: source movement (shared harness). Origin: #1204/#1205/#1206/#1220 harness files.
- Moved: `proxy.certificate_identity` test_sources. Its integration controls are in
  `certificate_identity_no_fallback_test.rs`, unchanged. Its production paths
  (`communication_assurance/certificate_identity_*`, `certificate_chain_evidence.rs`) are unchanged.
- The proposition holds; all 31 selectors resolve; nothing weakened.

### THM-0026 — Credential/key correspondence relates two independently interpreted keys and attributes every refusal to the side that failed — **CLEAN**
- Cause: dependency change (`boundary.tls_mechanism` digest; the unit crosses it through
  `delegated_tls/resolver.rs`). Origin: 37b522b2.
- Moved: `proxy.credential_key_correspondence` governing_boundaries only. No path of the unit
  changed (`git diff --stat` empty over its five paths).
- The boundary's trust statement and V0 cap are unchanged; the added path is the outbound
  connector, which this claim does not reach. Holds.

### THM-0027 — A delegated resolver's existence proves its credential and signer corresponded — **CLEAN**
- Cause: dependency change (boundary) + source movement (harness). Origin: 37b522b2; #1204–#1206.
- Moved: `proxy.delegated_resolver_materialization` governing_boundaries + test_sources;
  `proxy.delegated_resolver_materialization_sole_producer` governing_boundaries.
- `delegated_tls/resolver.rs`, `delegated_tls.rs`, `tls.rs` unchanged. The two integration
  selectors are in `tls_test.rs`, unchanged. Holds.

### THM-0048 — Every listener obtains its whole security posture through one listener state — **CLEAN**
- Cause: dependency change (boundary). Origin: 37b522b2.
- Moved: `proxy.listener_state_assembly` governing_boundaries only; its six paths unchanged. Holds.

### THM-0054 — Every production listener denies unknown client revocation status — **CLEAN**
- Cause: dependency change (boundary) + source movement (harness). Origin: 37b522b2; #1204–#1206.
- Moved: `proxy.client_certificate_posture` governing_boundaries + test_sources. Paths
  (`client_verifier.rs`, `client_revocation_posture.rs`, `crl_reload_worker/mod.rs`, `tls.rs`,
  `assembly.rs`) unchanged; selectors in `tls_test.rs`, `client_verifier_posture_test.rs` and
  `client_verifier.rs` unchanged. Holds.

### THM-0080 — Serving derives peer identity only from the credential the mechanism accepted — **CLEAN**
- Cause: source movement (harness). Origin: #1204–#1206.
- Moved: `proxy.serving_identity_provenance` test_sources. Paths `async_serve/**`,
  `blocking_mtls_harness/**`, `tls.rs` unchanged; `serving_identity_provenance_test.rs` unchanged. Holds.

### THM-0089 — A KMS or STS endpoint reaches the authority its text names — **CLEAN-NOTE**
- Cause: source movement (harness; `integration_kms_test` compiles the same `tests/integration/**`).
  Origin: #1204–#1206.
- Moved: `proxy.kms_endpoint_authority` test_sources. `kms_endpoint_policy/{mod,authority,endpoint}.rs`
  unchanged. Its integration selector is in `app_startup_characterization_test.rs` (additive diff only).
- **Note (ASM-0082):** THM-0089's machine-interpretation conjunct rests on ASM-0082 (`url` parse =
  what `ureq` connects to). `url` 2.5.8 and `ureq` 2.12.1 are unchanged in `Cargo.lock`, so the
  premise's measured versions still hold. But ASM-0082's own `review_requirement` is "Owner review
  on any change … to how the outbound agent is built", and 37b522b2 changed exactly that
  (`ureq` built with `default-features = false` and no `tls` feature; `.tls_connector(RootedConnector::public())`
  added in `binding.rs:38-41`). The premise's TEXT is still true (the change does not touch
  parsing, addressing or redirects), but its trigger fired: the owner should re-acknowledge
  ASM-0082 (no edit needed). This is not mechanically stale: an assumption's digest covers its
  entry text only.

### THM-0090 — A credential leaves this proxy only to the endpoint its rule admitted — **CLEAN-NOTE**
- Cause: implementation change (`public_roots.rs` new in the unit; `binding.rs` installs it) +
  dependency change (the unit now crosses `boundary.tls_mechanism`). Origin: 37b522b2 (RustSec/TLS repair).
- Moved: `proxy.outbound_destination` governing_boundaries + source_inputs. Mutation probes,
  test selection, structural probes unchanged.
- **The diff.** `binding.rs:38-41`: the agent is `AgentBuilder::new().redirects(0).timeout(timeout).tls_connector(RootedConnector::public())`,
  then the same provenance match (vetting resolver only for certificate-derived). `outbound_fetch/mod.rs:82-89`
  declares `mod public_roots` under the same five-feature cfg as `binding`/`resolver`.
  `public_roots.rs:25-116` builds one rustls `ClientConfig` over `webpki_roots::TLS_SERVER_ROOTS`
  (ring provider, `with_safe_default_protocol_versions`, no client auth), verifies the server
  under `ServerName::try_from(host)` where `host` is the `dns_name` ureq passes with IPv6 brackets
  stripped, and completes the handshake before returning the stream.
- **Adversarial checks against 6127939a:**
  | question | answer |
  |---|---|
  | Can the connector move the authority? | No. It never chooses a peer: it wraps the `io` ureq already connected (to the vetted authority, through the vetting resolver for certificate-derived destinations) and authenticates THAT name. |
  | Are redirects still refused? | Yes. `.redirects(0)` is unchanged and precedes the connector; the redirect control `an_agent_does_not_follow_a_redirect_and_never_reaches_the_second_authority` is unchanged and still selected. |
  | Is there a second client? | No production one. `git grep` for `AgentBuilder`/`ureq::get(` finds `binding.rs:38` in production; `kms_endpoint_policy/mod.rs:632,687` are inside `#[cfg(test)]` (from `:265`) and only parse; `examples/http_profile_client.rs` and `tests/integration_ext/cpstore_etcd_e2e_test.rs` are not production. With ureq's `tls` feature gone, an agent built elsewhere has NO TLS and refuses every `https` URL, which is fail-closed. |
  | Weaker TLS than before? | No. ureq 2's `tls` feature installed rustls + ring + safe default versions + the same Mozilla roots (through the webpki-roots 0.26 shim re-exporting 1.x). The roots are now webpki-roots 1.0.10, which REMOVES `emSign ECC Root CA - G3` (RUSTSEC-2026-0381), and rustls-webpki 0.103.16 rejects the distrusted emSign intermediates (RUSTSEC-2026-0382). Both narrow acceptance. No safe protocol version → `config: None` → every handshake refused. |
  | Bracket stripping a confusion vector? | No. `url` hosts only carry brackets for IPv6 literals; stripping yields the literal that `ServerName::try_from` parses as an IP address. A non-name is refused `InvalidInput` (test `a_name_that_is_not_a_server_name_is_refused`). |
- The proposition (authority named, redirect-free, one capability, `KmsEndpoint` sole producer
  via THM-0089) holds unchanged. The new controls (four `public_roots::tests`) are not THM-0090
  selectors; they are dispositioned as NP-290 (CD-20600..CD-20603), an unratified proposition.
- **Note 1 (ASM-0082 trigger):** as for THM-0089, "how the outbound agent is built" changed, so
  ASM-0082's own review requirement asks for an owner re-acknowledgement. Its text still holds.
- **Note 2 (scope):** THM-0090's scope is about the AUTHORITY NAMED, and its security consequence
  ("exactly one destination") tacitly relies on TLS authenticating that authority. That reliance is
  now carried by code inside the unit's paths and crosses `boundary.tls_mechanism`, but no
  registered assumption covers it: ASM-0070 is scoped to `client.transport_server_identity` and
  speaks of a root store holding "ONLY the configured server CA", which is false for the outbound
  connector (it holds the public Web PKI set). At class V0 this is admissible (the boundary's cap is
  V0), so nothing fails; but NP-290's ratification decision is where the owner should decide whether
  the outbound server-authentication property becomes a claim with its own premise (a public-Web-PKI
  sibling of ASM-0070) or stays an unratified proposition. No change to THM-0090's text is proposed.

### THM-0092 — A request whose replay state was not established does not dispatch — **CLEAN**
- Cause: source movement (harness). Origin: #1204–#1206.
- Moved: `proxy.replay_admission_gate` test_sources. `http_profile_dispatch.rs` and
  `core_projection.rs` unchanged; `http_profile_dispatch_test.rs` unchanged. Holds.

### THM-0100 — A replica's exposure to a key its document no longer enrols is confined to the serving interval it prints — **CLEAN**
- Cause: source movement (harness). Origin: #1206 (e2f097a6).
- Moved: `proxy.trust_posture_declaration` test_sources. `trust_plane/mod.rs` unchanged. Its
  integration selector is in the additive-only `app_startup_characterization_test.rs`. The
  startup-transcript normalizer change touches only the audit line, which this selector does not
  read. Holds.

### THM-0102 — A validated deployment's connection-age bound never exceeds the credential lifetime it reports as its exposure window — **CLEAN**
- Cause: source movement (harness). Origin: #1206.
- Moved: `proxy.client_credential_window` test_sources. `client_credential_window.rs`,
  `credential_currency_bound.rs` unchanged; integration selector body unchanged. Holds.

### THM-0103 — The epoch-bound session store resumes a session under the epoch that tagged it, and under no other — **CLEAN**
- Cause: dependency change (boundary). Origin: 37b522b2.
- Moved: `proxy.epoch_bound_session_store` governing_boundaries only; `auth_epoch.rs`,
  `resumption_binding.rs`, `resumption_acceptance.rs` unchanged. Holds.

### THM-0109 — The client transport verifies the proxy's server certificate against the configured CA, and a request body is never sent to a server it did not authenticate — **CLEAN-NOTE**
- Cause: dependency change (boundary digest; the unit crosses it via `mcp-re-transport/src/tls_config.rs`).
  Origin: 37b522b2.
- Moved: `client.transport_server_identity` governing_boundaries only. `mcp-re-transport/src/{lib,tls_config,client}.rs`
  and `mtls_client_test` unchanged. The proposition holds.
- **Note (ASM-0070 trigger):** the same repair moved `rustls-webpki` 0.103.15 → 0.103.16
  (`Cargo.lock`; `rustls` stays 0.23.46). ASM-0070's acceptability clause says it "stops being
  acceptable … if the pinned rustls or webpki version changes what path validation, name matching
  or validity checking accepts", and its review requirement names "the pinned rustls/webpki
  version". 0.103.16 does change what path validation accepts — it REJECTS paths through the
  distrusted emSign intermediates (RUSTSEC-2026-0382) — a strict narrowing that cannot admit a
  certificate 0.103.15 refused. The premise's text remains true; its trigger fired, so the owner
  should re-acknowledge ASM-0070 against 0.103.16 (no edit needed; not mechanically stale). The
  client transport uses only the configured CA, so the webpki-roots change does not reach it.

### THM-0131 — The client-revocation posture states what this replica is enforcing now — **CLEAN**
- Cause: source movement (harness). Origin: #1204–#1206.
- Moved: `proxy.client_crl_next_update_gate` test_sources. `client_crl_publication.rs` unchanged;
  `crl_freshness_rejects_malformed_der` in unchanged `tls_test.rs`. Holds.

## Assumptions touched (for the owner, not theorem verdicts)

| assumption | text still true? | own trigger fired? | action |
|---|---|---|---|
| ASM-0070 (rustls WebPkiServerVerifier, client transport) | yes | yes — webpki 0.103.15 → 0.103.16 (narrowing) | owner re-acknowledge; no edit |
| ASM-0082 (`url`/`ureq` addressing, redirects) | yes — url 2.5.8 / ureq 2.12.1 unchanged | yes — "how the outbound agent is built" changed (connector, no `tls` feature) | owner re-acknowledge; no edit |

Neither is reported stale by `review`/`check-assumptions`, because an assumption's digest covers
its entry, not the dependency versions its prose names. The outbound public-roots server
authentication has no premise of its own (THM-0090 Note 2 / NP-290).

---

# B5 — admission, continuation, coordinates, retention, posture selection (11 theorems)

Candidate `exec/1201-pre-assurance @ 6127939a`. Baseline `origin/main @ 8262c5fa` (133/133 REVIEWED).
Read-only. Diffs are `git diff 8262c5fa..6127939a -- <unit paths>`. Test-selection rows read from
`verification/generated/rust-targets.json` at both revisions. Slice map: 6fd82e55 = #1202,
f900b805 = #1204, ab46131a = #1205, e2f097a6 = #1206, bc8cde82 = #1220.

## The changes behind this batch

1. **Shared async test-target row (f900b805, #1204; ab46131a, #1205).** `//mcp-re-proxy:integration_async_test`
   and `integration_async_ext_test` gained crate feature `audit_commitment_reference`, and their
   source sets gained `intent_before_dispatch_test.rs` and `outcome_before_success_test.rs`.
   That moves `test_selection` (the target row) and `test_sources` (the target's srcs) of EVERY unit
   whose battery runs in those targets, with no change to the unit's own tests.
   - The feature is additive only. Every item it gates is `#[cfg(any(test, feature = "audit_commitment_reference"))]`:
     the reference authority (`audit_commitment/{reference,harness,forgery,reference_probe,reference_step}.rs`),
     `ProviderId::reference`, `AuditProviders::with_reference_for_test`, `HttpProfileProxy::with_required_audit_commitment`
     (`dispatch_commitment.rs:183`), and the `lib.rs:330` re-export. No existing code path changes
     under it; a proxy built without a required posture serves exactly as before.
   - `delegated_client_server_e2e_test.rs` (6fd82e55, f900b805): `build_server_with_kid` now delegates to
     `build_server_over(canned_inner(), 300)` — the same inner and TTL — and `client_proxy_with_revocation`
     to `client_proxy_over_with(Box::new(InProcessServer::new(server, NOW)), revocation)`, the same
     transport. Three tests ADDED (D9 coordinate, pre-acceptance scope, envelope facets). No assertion removed.
2. **Shared sync test-target sources (6fd82e55, e2f097a6, f900b805).** `//mcp-re-proxy:integration_test` gained
   `prepared_dispatch_source_test.rs` (new); `app_startup_characterization_test.rs` +188/-0;
   `exchange_transition_ownership_test.rs` +17/-0. `tests/startup_transcript/mod.rs`: the `AuditSink`
   event gained `delivery`, and the normalizer now reads the production OFF line — the baseline matcher
   looked for `record = NONE`, a string production never wrote, so it would have panicked on the OFF line.
   Only that matcher was removed; two normalizer tests were added. No assertion weakened.
3. **`self.audit` became an `AuditPosture` (f900b805, #1204).** Refusal sites pass `self.audit.observer()`
   where they passed `&self.audit`. The observer is the same `MaybeAuditSink`.

Every test file that the batch's own `tested_symbols` name is byte-unchanged:
`per_request_revocation_test`, `pdp_authorization_serving_test`, `transparency_e2e_test`,
`admission_currency_serving_test`, `outstanding_id_provenance_test`, `continuation_installation_test`.

---

### THM-0032 — Per-request credential currency is decided from the credential the mechanism accepted — **CLEAN**

- **Cause:** source movement (shared async test-target inputs only). **Origin:** f900b805 (#1204), ab46131a (#1205).
- **Moved:** `proxy.per_request_revocation_serving` test_selection + test_sources.
- **Diff:** unit paths (`async_serve/request.rs`, `async_serve/connection.rs`, `client_revocation.rs`) unchanged.
  The five `per_request_revocation_test::*` selectors are unchanged, and so is their file. Change 1 only.
- **Adversarial:** could the new feature alter the warm-connection CRL path? No: none of the gated items
  is reached from `async_serve` request handling.
- **Evidence:** the battery bears unchanged.

### THM-0040 — An authorized request was permitted by a decision about that very request — **CLEAN**

- **Cause:** source movement (shared async test-target inputs). **Origin:** f900b805, ab46131a.
- **Moved:** `proxy.pdp_decision_relation` test_selection + test_sources.
- **Diff:** `authorization/pdp/*`, `authorization/{request,verified_actor,verified_action}.rs` unchanged.
  The `pdp_authorization_serving_test` file and the unit-test selectors are unchanged. Change 1 only.
- **Adversarial:** no PDP input, conjunct or ordering touched. The G1 gate sits after authorization,
  so it cannot pre-empt or replace a Permit.
- **Evidence:** bears unchanged.

### THM-0069 — A security record states each authority's outcome in that authority's own coordinate — **CLEAN-NOTE**

- **Cause:** source movement (`audit_record/mod.rs`) plus shared async test-target inputs.
- **Origin:** 6fd82e55 (#1202), f900b805 (#1204), ab46131a (#1205), e2f097a6 (#1206).
- **Moved:** `proxy.audit_authority_coordinates` source_inputs + test_selection + test_sources;
  `proxy.admission_currency_gate` test_selection + test_sources.
- **Diff, `audit_record/mod.rs`:**
  - adds the submodules `accounting`, `emission`, `envelope`, `intent` and their re-exports;
  - `record_to` MOVES to `audit_record/emission.rs:28` (unit `proxy.audit_delivery`). Its
    `catch_unwind` around `sink.record` is kept (`emission.rs:70`, `:85`), and so is its test
    `a_panicking_sink_loses_the_record_and_does_not_unwind_into_the_request` (`emission.rs:110`);
  - `AuditRecord`'s fields, `subject.rs` and `authority_verdicts.rs` are unchanged;
  - the tests `the_two_coordinates_stay_separate_on_one_record`,
    `a_whole_record_renders_its_own_six_fields_in_order_with_the_minted_decision_spellings` and
    `no_two_authorities_name_the_same_field_on_one_record` are unchanged.
- **Adversarial:**
  - Can the envelope re-route a coordinate? No. `AuditEnvelope` wraps the produced `AuditRecord`, and
    the new e2e test `the_envelope_keeps_the_verifier_resolved_actor_and_both_facets` asserts that both
    facets and the canonical bytes carry what the serving path produced.
  - Is a response record now given an authorization coordinate? No: that test asserts
    `envelopes[1].record().subject.authorization().is_none()`.
- **Note for the owner:** the epic adds two committed fact kinds that are NOT `AuditRecord`s:
  - `execution.intent` (`audit_record/intent.rs`): event, actor, at. "No `decision` … no `reason` … no `status`."
  - `mcp-re.audit.accounting` (`audit_record/accounting.rs`): no actor, no reason.

  Neither is a request record or a response record, so both fall outside THM-0069's quantifier. Neither
  states any authority's outcome, which is consistent with the claim and with D1/D2/Q3. No change to
  THM-0069 is needed. A scope sentence naming them as out of quantifier would only document it.
- **Evidence:** bears. The coordinate battery is unchanged.

### THM-0077 — No deployment serves a posture nobody selected — **CLEAN-NOTE**

- **Cause:** implementation change (a new security capability, the audit commitment posture, in
  supporting units), plus shared sync harness inputs.
- **Origin:** e2f097a6 (#1206); bc8cde82 (#1220) for the `audit_posture.rs` text.
- **Moved:**
  - `proxy.delegated_signing_configuration_state`: test_sources
  - `proxy.evidence_retention_state`: source_inputs
  - `proxy.legality_boundary_totality`: source_inputs + test_sources
  - `proxy.serving_capability_posture`: mutation_probes + source_inputs + test_selection
  - `proxy.transport_binding_and_crl_state`: test_sources
  - `proxy.trust_composition_root`: source_inputs + test_sources
  - `proxy.unestablishable_capability_refusal`: mutation_probes + source_inputs + test_sources
- **Diff:**
  - `config_state/evidence.rs`: the `Audit` machine LEAVES this file for `config_state/audit_policy.rs`,
    because it gained a refusal. Retention and VerifiedContext are unchanged, and their tests are
    re-indexed only (`.1` → `.0`).
  - `config_state/audit_policy.rs:40-55`: four request forms. `(None, Required)` is refused with
    `REQUIRED_WITHOUT_OBSERVER` (S4); the other three classify.
  - `validation/{mod,machine_violations,recognition}.rs`: the audit clause joins `legality_violations`
    (the `MachineViolations` destructure is exhaustive at compile time). Recognition now reads
    `r.audit.ok_or_else(|| unrecognised("audit"))`, so an unrecognised audit machine is an internal
    error where it was a pass-through. That is stricter. A doc paragraph listing the old rejected
    postures was replaced by "each machine's own column"; no rejection logic moved.
  - `app.rs` + `app/entry.rs`: the doors `run`, `run_request` and `run_with` resolve
    `AuditPlan::resolve(state, providers, …)` BEFORE `run_validated` (`entry.rs:34-38`). A
    resolution refusal returns `Err` through `drained`. `run_validated` establishes the provider before
    any plane (`app.rs:216-218`), and `serving_capabilities/audit_posture.rs:48-70` maps an
    establishment failure to `Err` (startup refusal). There is no arm that yields best-effort from a
    required plan: `without_commitment()` returns `Err(required)` for a required plan.
  - Mutation probes:
    - **M461** is re-anchored to `audit_posture.rs` (`return Ok(Established::off(format!("{AUDIT_OFF}{unused}")))`).
      The weakening "OFF installs a sink" is the same. Its killer is now
      `best_effort_keeps_its_meaning_and_installs_what_its_line_says`, which asserts `off.is_none()`,
      so it is still killed.
    - **M358** is re-anchored to `entry.rs:39` with the same weakening (`.or_else(|_| Ok(()))`
      around `run_validated`).
- **Adversarial:**
  - Can `--audit-commitment required` be served as best-effort or OFF? No: validation, entry and
    materialization each refuse (above).
  - Can best-effort silently gain a provider? No: a registered provider under best-effort is named
    and unused, and the test `an_unused_provider_is_named_and_not_promoted` asserts zero requests.
  - Did any other capability's legality change? No.
- **Note for the owner (evidence closure):** the audit posture is a new "security capability held by
  the serving runtime", so it is inside THM-0077's universal statement. But its refusals and their
  controls live in unit `proxy.audit_posture`, which supports THM-0135 and THM-0136, not THM-0077:
  - `config_state/audit_policy.rs` with `required_without_an_observer_is_refused_not_downgraded`;
  - `audit_commitment/plan.rs` (required with no provider);
  - `app::entry::tests::the_default_entry_refuses_a_required_deployment_before_any_effect`.

  At baseline the (then total) Audit machine was inside THM-0077's closure, in
  `proxy.evidence_retention_state`. `proxy.unestablishable_capability_refusal` now lists `entry.rs` in
  its paths, but its tested symbols do not cover the audit refusal. The proposition holds. This is the
  same shape as the v0.18.1 NP-281 note.
  - **Recommendation:** at THM-0077's re-review, add `unit://proxy.audit_posture` to THM-0077's
    `supported_by`. Or, once THM-0135 is ratified, add `THM-0135` to its `depends_on`, as THM-0096 and
    THM-0090 are composed.
  - **Cost:** either is a claim/support edit to a stale theorem that must be re-reviewed anyway. No
    other fingerprint moves except THM-0077's dependants' dependency digests.
- **Evidence:** bears for every pre-existing capability.

### THM-0083 — What a request is, is decided once, before anything reads it for meaning — **CLEAN**

- **Cause:** source movement. **Origin:** f900b805 (#1204), ab46131a (#1205), bc8cde82/7b6ab1a8 (doc comments).
- **Moved:** `proxy.outstanding_id_provenance` source_inputs + test_sources.
- **Diff:**
  - `http_profile_serve/mod.rs:488-506`: the notification branch and the reply assembly moved into
    `reply_assembly/dispatched.rs::answer_dispatched`, which receives `outstanding` — the value
    `admitted.envelope.outstanding()` decided once — and branches on `outstanding.is_notification()`
    (`dispatched.rs:35`). The `CARRIED` string is still at `mod.rs:496`.
  - `pre_admission/mod.rs:74`: `self.audit.observer()`.
  - In serving production code, `validate_request_envelope(` is still called once
    (`request_admission.rs:166`). The other hits (`reply.rs:146`, `body_boundary.rs:274`) are in test
    modules.
  - `outstanding_id_provenance_test.rs` is unchanged; it scans the whole `http_profile_serve/` subtree,
    `dispatched.rs` included.
- **Adversarial:** could G1/G2 re-read the body's id? Neither `dispatch_commitment.rs` nor `success_exit.rs`
  reads `.outstanding()`; the 202 decision uses the carried value.
- **Evidence:** bears.

### THM-0093 — An answer leg that needs a continuation does not proceed unbound — **CLEAN**

- **Cause:** source movement. **Origin:** f900b805 (#1204).
- **Moved:** `proxy.continuation_leg_binding` source_inputs.
- **Diff:** `answering_commitment.rs:93`: `&self.audit` → `self.audit.observer()` in the refusal call.
  That is the only change in the unit.
- **Adversarial:** no read, spend or attribution path touched.
- **Evidence:** bears. The 12 unit selectors are unchanged.

### THM-0096 — The runtime installs exactly the continuation capability its plan names — **CLEAN**

- **Cause:** implementation change in a co-located, unrelated authority (the audit entry and posture
  in `app.rs`), plus shared sync harness inputs. **Origin:** 6fd82e55 (#1202), e2f097a6 (#1206).
- **Moved:** `proxy.continuation_installation` source_inputs + test_sources.
- **Diff:** `app.rs`:
  - the three entry functions moved to `app/entry.rs`;
  - `run_validated` takes an `AuditPlan` and establishes it first;
  - the security-audit seam installs an `AuditPosture`;
  - a test now records through `record_to`.

  The continuation materialization and installation code is unchanged, and so is
  `continuation_installation_test.rs`.
- **Adversarial:** a required audit refusal at startup refuses before any continuation store is
  installed, so no store is ever announced OFF in its place.
- **Evidence:** bears.

### THM-0112 — A retained hop is exactly what re-verifies it — **CLEAN**

- **Cause:** source movement (shared async test-target inputs). **Origin:** f900b805, ab46131a.
- **Moved:** `proxy.retained_record_content` test_selection + test_sources.
- **Diff:** `transparency/{retained_record,covered_set}.rs` unchanged; `transparency_e2e_test` unchanged.
- **Adversarial:** Q2 moved WHEN retention completes relative to G2, which is THM-0088's concern and is
  out of this claim's scope by its own text. WHAT is retained is untouched.
- **Evidence:** bears.

### THM-0113 — An attestation is checked against the bytes it was issued over — **CLEAN**

- **Cause:** source movement (shared async test-target inputs). **Origin:** f900b805, ab46131a.
- **Moved:** `proxy.evidence_attestation` test_selection + test_sources.
- **Diff:** `transparency/attestation.rs` unchanged; the test file unchanged. It is off the request path by
  premise, so it is unaffected by G1/G2. Its `depends_on` THM-0088 is stale elsewhere for semantics only
  (no claim movement).
- **Evidence:** bears.

### THM-0129 — Authoritative admission state is authenticated and bounded-current — **CLEAN**

- **Cause:** source movement (shared async ext test-target row). **Origin:** f900b805.
- **Moved:** `proxy.admission_state_source` test_selection + test_sources.
- **Diff:** `admission_source/*` and `redis_admission_source/*` unchanged; the selectors are unchanged. The ext
  target row gained `audit_commitment_reference`, which is additive.
- **Evidence:** bears.

### THM-0132 — A replica serves on last-known admission state for at most P — **CLEAN**

- **Cause:** source movement. **Origin:** f900b805 (#1204).
- **Moved:** `proxy.admission_currency_gate` test_selection + test_sources;
  `proxy.admission_gate_unskippable` source_inputs.
- **Diff:** `pre_admission/mod.rs:74`: the request-verification refusal passes `self.audit.observer()`.
  That is the only line. `standing.rs` and `action.rs` (the gate) are unchanged, and so is the admission
  window code.
- **Adversarial:** the gate's position is unchanged, and so is the window clock; G1 sits after admission.
- **Evidence:** bears.

---

# B6 — audit delivery, refusal emission, and the two new G1/G2 theorems (re-review at 6127939a)

Candidate `exec/1201-pre-assurance @ 6127939a` (local). Baseline `origin/main @ 8262c5fa`, where every
theorem was REVIEWED. Read-only. No review record written. All evidence below is class V0
(tests, source scans, structural and mutation probes); none of it is a machine-checked proof.

| item | proposed verdict | cause | origin |
|---|---|---|---|
| THM-0070 | CLEAN-NOTE | implementation change | #1202 6fd82e55, #1203 70a4651f, #1206 e2f097a6, #1220 bc8cde82 |
| THM-0085 | CLEAN | implementation change (plumbing) | #1202 6fd82e55, #1203/#1206 (posture), #1204 f900b805 / #1205 ab46131a (tail split), #1220 |
| THM-0135 | CLEAN — ratify | missing review (new) | #1204 f900b805, #1206 e2f097a6, #1207, #1220 bc8cde82, 7b6ab1a8 |
| THM-0136 | CLEAN-NOTE — ratify after D7 | missing review (new) | #1205 ab46131a, #1206, #1207, #1220 bc8cde82/a676dfd5, 7b6ab1a8 |
| ASM-0089 | CLEAN — ratify | missing review (new) | #1207, 7b6ab1a8 (D6) |
| ASM-0090 | CLEAN-NOTE — ratify after D8 | missing review (new) | #1207, 7b6ab1a8 (D6) |
| ASM-0091 | CLEAN — ratify | missing review (new) | #1207, 7b6ab1a8 (D6) |

Fingerprints at 6127939a (`tools/verification/review --fingerprint`):

| theorem | fingerprint | review digest |
|---|---|---|
| THM-0070 | `sha256:dd38b842fb857af412fae0c08d241373fd6f7dcec05c3ac7802ca72b7e5269e1` (= reviewed; claim unchanged) | `sha256:70c3a0d367b0efc68431af45775f645aa4e783ff873ddcf441bfd71c6b03d7e5` |
| THM-0085 | `sha256:f39497f8ded64f01ddd3473783578ac80f0419bc6d4c875ae833319bdda0005f` (= reviewed; claim unchanged) | `sha256:2a47563002429ff49870a8a501fb11936b90c451661022b184d10dcd8ee42fdc` |
| THM-0135 | `sha256:df790c7b287331ca3f4924495e606485937e432de42f4e938d9eb58936bbeaae` | `sha256:5c56fd7c972d175937aa02f546eb6540168df9a40f1317f6f93078acb7488917` |
| THM-0136 | `sha256:ac9a20e314426b789c256903816a77a5edeff9f58f82bfebcb5071b856ea5311` (moves if D7 lands) | `sha256:5e66730cf2b671cc047f8d0f55580e6240d130657ab04e26c25c8f2d8283b6ec` |

## The change behind this batch

#1202 (6fd82e55) moved event identity from the stderr sink to production. Before, `StderrAuditSink`
numbered each line from its own `AuditPositions` counter at offer time (`audit_sink/stream.rs` @
8262c5fa). Now `audit_record::produce` allocates `(run, seq)` once, from the one process
allocator (`audit_record/envelope/allocator.rs:53-58`, a checked `fetch_update`, no wrap, permanent
`SequenceExhausted` after `i64::MAX - 1`), and fixes the canonical bytes. The sink renders the
identity it is handed (`audit_sink/stderr.rs` `audit_line`, `record`). The emission funnel
`audit_record/emission.rs:28-49` produces every decision whatever observer is installed, then
offers it (`offer`, panic-contained, `:80-88`).

#1203/#1206 put the observer behind `AuditPosture` (`http_profile_serve/mod.rs` field `audit`,
`self.audit.observer()`), and under the required posture three event kinds are numbered from the
same allocator but committed to the provider rather than offered to the observer: the intent
(`audit_commitment/intent.rs:74`), the accounting record (`cadence.rs:75`) and a G2 outcome whose
commitment failed (`outcome.rs:62`). Under best-effort none of these run, and every produced
event is offered.

## THM-0070 — The record stream is honest about what reached it — **CLEAN-NOTE**

- **Cause:** implementation change. Moved: `proxy.audit_delivery` mutation_probes, source_inputs,
  test_selection, test_sources. The unit's `paths` gained `audit_record/emission.rs` and the
  eleven `audit_record/envelope/*` files (#1202), which is where the numbering now lives.
- **Statement, element by element, at 6127939a:**
  - *Every emitted record carries its position (seq within a named run).* Holds: the identity is
    the event's (`stderr.rs` `audit_line(&envelope.id(), …)`), and the stream's run is the
    allocator's run by construction (`StderrAuditSink::open` takes `open_process_run()`).
    Test `every_line_names_its_run_and_its_number_in_that_run` now asserts the envelope's run
    equals the stream's.
  - *Collector preserves emission order; full queue drops, never blocks; drop count reported
    without a following record; unattributed flood bounded; concurrent offers at the ceiling.*
    `offer` (`audit_sink/mod.rs`) is the same reservation logic, now also returning whether the
    line was queued (consumed by `observer_accounting::count_offer`). `admission_ceiling` is fed
    `envelope.record()` — the same attribution input. `writer.rs`: one string changed (the drop
    report text, below). `drain.rs`: type rename only (`AuditIncarnation` → `RunId`).
  - *Drain acknowledged vs UNKNOWN.* Unchanged.
- **Tests:** none removed. The six `audit_sink::stream::tests` moved to
  `audit_record::envelope::{allocator,run_id}::tests` under the same names, and
  `tested_symbols` follows them. Added: `a_record_line_is_byte_identical_to_v0_18_1`,
  `an_exhausted_run_says_so_once`, `the_stream_lines_name_the_opened_run`.
- **Probes:** M150, M151, M168, M169, M493, M494, M495 resolve, each anchor exactly once in a
  production half. M494 is re-anchored to `audit_record/envelope/event_id.rs`, and its killer to
  `allocator::tests::a_position_has_no_number_in_another_run` (the only mutation_probes change).
- **NOTE 1 (the owner should see; open item O4/B3).** "A dropped record is a numbered hole" still
  holds, but under the **required** posture the observer's stream also has holes that are not
  drops: intent, accounting and G2-failed outcome events take a `seq` and are never offered
  (`emission.rs:52-55` says so). The statement never claims gap ⇒ drop, so it stays true. The
  disclosure is in code: the startup posture line (`serving_capabilities/audit_posture.rs:145`,
  `:235` "gaps that are not drops") and the drop report (`writer.rs` "among its seq gaps; a
  required posture's other gaps are named at startup"). Whether D1's "v0.18.1 contract
  unchanged" is scoped to best-effort is the owner's O4 ruling. Under best-effort the gap ⇔
  drop reading is exactly as on main.
- **NOTE 2.** Seq exhaustion now drops every later decision from the stream with one warning
  (`stderr.rs` `state_unnumbered`), and those decisions are not counted in `dropped=`. On main
  the counter would have been rendered as `i64::MAX` forever. Both are unreachable in practice
  (`i64::MAX` events). The new behaviour is more honest: the run says it stopped numbering.
- **Outside the claim, for completeness:** `pub trait AuditSink` changed shape (`record` takes an
  `&AuditEnvelope`, and there is a new `unnumbered`). That affects an external embedder's sink, not this claim.

## THM-0085 — Every exchange-owned refusal reaches the audit boundary, typed, before it is answered — **CLEAN**

- **Cause:** implementation change, plumbing only. Moved: `proxy.refusal_audit_emission`
  source_inputs, test_sources.
- **Diff:**
  - `receipt/audit_event.rs`: `Accepted` carries the `ExchangeCoordinate` its `request.accepted`
    record established (D9).
  - `record_to` gains the coordinate argument (`None` for request records).
  - `response_rejection` takes the coordinate and passes it to `record_to`, which is still called
    BEFORE `self.signed_rejection(`.
  - `receipt/mod.rs`: the funnel passes `acc.exchange_coordinate()`.
  - `http_profile_serve/mod.rs`: `&self.audit` became `self.audit.observer()`, and the post-dispatch
    tail moved to `answer_dispatched`.
  - `inner_plane` became `pub(crate)` for the one type `NotificationDelivered`; the justification
    is at the point of widening.
- **The new refusals pass the same funnel.**
  - G1's `audit_commitment_unavailable`: `dispatch_commitment.rs:55-66` `refuse_accepted` →
    `self.responses.refuse`.
  - G2's refusal: `success_exit.rs` → `accepted.rs:90` `refuse_retained` → `response_rejection`
    (`accepted.rs:148`).
  - The notification error path: `notification.rs:53`.
  - The unsigned last-resort body is built inside `signed_rejection` (`receipt/artifact.rs:75-79`,
    unchanged since main), so it too comes after the record.
- **Control:** `refusal_audit_emission_test.rs` is unchanged. It walks the whole serving
  subtree, so the new files are scanned, and `EMITTER_ROUTES = 5` still holds; the battery is
  green at this head per the orchestrator's run. M279 resolves.
- `depends_on` (THM-0046, THM-0069, THM-0081) is unchanged at the claim level.

## THM-0135 — Required posture: no dispatch without a committed, redeemed intent — **CLEAN (first review; ratify)**

- **Claim:** under `--audit-commitment required`, every admitted exchange is dispatched only from
  `ReadyForDispatch`, which needs an intent disposition. Under required, that disposition is only
  a redeemed `Intent` witness, which:
  - was minted from a receipt that matches the SENT envelope: identity, digest, crossing and tier;
  - is spent once, against this exchange's intent event and the same `Arc` provider instance;
  - was produced at the `request.accepted` coordinate under a fresh identity.

  Every G1 failure refuses before dispatch with `mcp-re.audit_commitment_unavailable`:
  - 503 when a retry can succeed, 500 otherwise;
  - signed, or the unsigned last-resort body;
  - with a pre-dispatch disposition that never states success: NothingExecuted,
    ApprovalSpentNothingExecuted, or PossiblyExecuted only under a latched anomaly;
  - with the retention reservation rescinded.

  A required posture is never served as best-effort. "Committed" is the proxy's fact, not a
  persistence claim.
- **Code at 6127939a:** identical to cf630140 for every supporting unit (`git diff cf630140..6127939a`
  touches no `audit_commitment` source). The statement-to-code table in `s2-thm.md` §"THM-0135"
  stands:
  - `intent.rs:68-83` (order), `:98-115` (status mapping);
  - `established/mod.rs:135` (spent budget is Unavailable);
  - `http_profile_serve/mod.rs` `disposition` via `dispatch_commitment.rs:55-66`;
  - `not_required.rs:25` (`minted_by_posture` is `pub(in crate::audit_commitment)`);
  - `posture.rs:103-118`.
- **Units:** `proxy.audit_intent_gate`, `proxy.audit_intent_gate_sole_producer`,
  `proxy.audit_commitment_witness`, `proxy.audit_commitment_sole_producer`, `proxy.audit_posture`.
  `depends_on = []`, which is correct: G1 rests on no other theorem's claim. Premises: ASM-0089,
  ASM-0090 and ASM-0091 (the premise axis in `review --json`).
- **Hostile controls:**
  - S61-S69 (on `proxy.audit_commitment_sole_producer`) and S70-S75 (on
    `proxy.audit_intent_gate_sole_producer`): 15 of 15 resolve. They cover a forged witness or
    receipt, `NotRequired` minted outside the posture owner, and a `ReadyForDispatch` without a
    disposition.
  - M596-M625: 30 of 30 resolve, each anchor exactly once in a production half.
  - Killers sit in `proxy_unit_test`, or under `#[cfg(feature = "audit_commitment_reference")]
    mod required` in `integration_async_test` / `integration_async_ext_test`, which set that
    feature. A lane without it compiles them to zero tests.
  - The serving-path controls run only against the scripted reference authority. The production
    route `app::entry` → `AuditPosture::required` is exercised through startup establishment only.
- **Evidence class:** V0. Machine A is a test-only Rust model, never extracted; there is no
  Verus, Lean or Aeneas artifact. The scope says so ("Class V0: tested, mutation-probed and
  structurally probed, not proved").
- **Failure model:** provider outage, saturation, a spent budget, a timeout, a dropped
  completion, a panic, a forged, stale or mismatched receipt, an absent coordinate, an identity
  failure, cancellation during G1. Each refuses before dispatch.
- **Cosmetic, no action:** one physical line of the statement runs long ("A request dropped during
  G1 dispatches nothing. A posture requested as required is never served as best-effort: startup
  refuses it"). Rewrapping would move the claim digest for no semantic gain.

## THM-0136 — Required posture: no completed success visible without a committed, redeemed outcome — **CLEAN-NOTE (first review; ratify after D7)**

- **Claim:** all three success terminals leave through the one exit, `publish_success`
  (`success_exit.rs:40-79`), in this order:
  1. G2: `self.audit.outcome(intent, coordinate, observed)`, with requiredness carried from G1
     (`posture.rs:125-143`; the impossible (Committed, BestEffort) arm refuses);
  2. retention completes (`retain_accepted`);
  3. the observer is offered the COMMITTED envelope itself (`offer_outcome`, `offer_produced`);
  4. `progress.publish(success)`;
  5. `served(response)`.

  Every G2 failure is a 500 `AuditCommitmentUnavailable` (`outcome.rs:78`) served by
  `refuse_retained`. The failure states PossiblyExecuted, because `BackendDispatched` was
  advanced before the dispatch await. Retention completion is attempted with the refusal, and a
  failure leaves `.pending`. A retention failure after a committed outcome is
  `evidence_retention_indeterminate` (W5b). No success bytes are served on either path.
- **Code at 6127939a:** as above, and the same as cf630140 apart from C1. C1 adds
  `dispatched.rs` to `success_exit_is_the_only_success_served_call`; the orchestrator's poison
  pill (a `served(` call in `dispatched.rs`) turned it red.
- **Units:** `proxy.audit_outcome_gate` plus the four shared units. `depends_on = ["THM-0101"]`
  is correct: "a terminal only through publication" is THM-0101's claim. THM-0101's corrected
  text (6127939a) moves THM-0136's `theorem_dependencies` component. That is expected, and is
  why THM-0136 is reviewed at this head. Premises: ASM-0089 to ASM-0091.
- **Hostile controls:**
  - Source scans: `success_exit.rs` (order; single served call over `accepted.rs`,
    `dispatched.rs`, `notification.rs`, `mod.rs`), `accepted.rs:192-215`,
    `notification.rs:132-150`.
  - M615-M619.
  - S66 and S73 reach the outcome types. No structural probe covers the exit, and the scope now
    says so (D3, landed in 7b6ab1a8).
- **Evidence class:** V0, stated in the scope.
- **D7 — DRAFTING, apply before ratification (THM-0136 is unreviewed, so it costs nothing now).**
  - **Problem 1.** The scope says the 202's terminal is "entered only by opening the carrier the
    inner plane mints when the message was delivered". THM-0101's corrected text (6127939a) says
    the opposite of "opening": nothing but `establish` opens a carrier, and the 202's carrier is
    READ by `ServedSuccess::tail` for its event alone, with its product never yielded
    (`exchange_state.rs:365-374`, `:725-729`). The two records should not disagree.
  - **Problem 2.** "The source-scan tests over `success_exit.rs`, `accepted.rs` and
    `notification.rs`" names where the tests live, but after C1 the scan reaches `dispatched.rs`
    and `mod.rs` too.
  - **Replacement for the first:** "the 202's terminal entered only through the carrier the
    inner plane mints when the message was delivered, whose event alone the publication reads".
  - **Replacement for the second:** "the source-scan tests in `success_exit.rs`, `accepted.rs`
    and `notification.rs`".
  - **Fingerprints moved:** THM-0136's claim and review digests only. No theorem depends on
    THM-0136.
- **Already-tracked, not claim defects:**
  - **N3 (O5):** the signing window does not cover the G2 wait; THM-0136 claims nothing about it.
  - **B3 (O4):** see THM-0070 note 1.

## ASM-0089 — Provider receipt means commitment at the declared tier — **CLEAN (ratify)**

- **Seam:** `CommitmentAuthority::{commit, declared_tier}` (`audit_commitment/authority.rs`).
  `check-assumptions` resolves the `sites` entry, and the `boundary.audit_commitment_provider`
  record agrees.
- **Text:** "proposed, not yet ratified" is gone from `introduced_by` (D6, 7b6ab1a8), so a
  ratification pins no phrase that must later change.
- **Scope:** the four safety units plus the boundary. That is correct, because "committed" is
  defined against this premise.
- **Non-claims are explicit:**
  - a lying or Byzantine provider is outside the model;
  - network-receipt providers (`XADD` reply, `WAIT`, TCP ack, HTTP 2xx) do not qualify;
  - no exactly-once delivery, no unconditional permanence;
  - "a Rust proof never establishes it".
- **Reference authority:** it is test-only. The `*_pre052` flavors that link it are
  `testonly = True`, and the open-source binary registers no provider.

## ASM-0090 — Conditional liveness and archival — **CLEAN-NOTE (ratify after D8)**

- **Content:** it agrees with ADR-070 L1, L3, P10, §8 and §12. Deduplication is on the event
  binding (identity plus digest), never on transport position. It is stated as a liveness
  condition, never a safety one.
- **D8 — DRAFTING, apply before ratification (the assumption digest covers the whole entry).**
  - **Problem.** The justification says an exchange that cannot be committed "is refused,
    before dispatch with `NothingExecuted` or after it with `PossiblyExecuted`". Since the
    THM-0135 correction (R6) and ADR §6 (D-3, 7b6ab1a8), a pre-dispatch refusal can also state
    `ApprovalSpentNothingExecuted`, or `PossiblyExecuted` under a latched anomaly.
  - **Replacement:** "before dispatch with a disposition that never states a success
    (`NothingExecuted`, or `ApprovalSpentNothingExecuted` where a continuation approval was
    already spent), or after it with `PossiblyExecuted`".
  - **Fingerprints moved:** the ASM-0090 digest, hence the `trusted_assumptions` of
    `proxy.audit_commitment_witness`, `proxy.audit_intent_gate`, `proxy.audit_outcome_gate` and
    `proxy.audit_posture`, hence THM-0135's and THM-0136's review and premise digests. All are
    unreviewed, so nothing currently REVIEWED moves.
- **Coupling (O3, the owner's choice):** an edit here stales both safety theorems. Decoupling
  needs a separate liveness unit (see `s2-thm.md` §L). The current coupling is safe: it errs
  toward extra review and never yields false currency.

## ASM-0091 — Finite provider capacity — **CLEAN (ratify)**

- **Content:** one try-acquired budget per established provider serves G1, G2 and the cadence
  (`budget.rs`, `established/mod.rs:135`, `cadence.rs:78`). It is separate from the observer
  queue and from retention `MAX_RESERVATIONS`.
- **What saturation costs at each crossing:**
  - G1: a 503 before dispatch;
  - G2: a 500 PossiblyExecuted after dispatch;
  - the cadence: a missed interval, with no request refused.

  Each is tested: `a_spent_budget_refuses_before_dispatch_and_the_observer_is_unaffected`,
  `every_outcome_failure_is_500`, `a_spent_budget_is_a_missed_interval_not_a_wait`.
- **Scope:** correct. It omits `proxy.audit_commitment_witness`, which has no capacity logic.
- **Same coupling note as ASM-0090.**

## Proposed owner disposition for this batch

1. Apply D7 (THM-0136 scope) and D8 (ASM-0090 justification) now, while all five items are
   unreviewed; then regenerate views and re-measure THM-0135, THM-0136 and the three ASMs.
2. Ratify THM-0135 and THM-0136 at the post-D7/D8 fingerprints, and ASM-0089, ASM-0090 and
   ASM-0091 at their post-D8 digests.
3. Re-record THM-0070 (CLEAN-NOTE, notes 1-2) and THM-0085 (CLEAN) at the review digests above.
   Their claims are unchanged.

---
