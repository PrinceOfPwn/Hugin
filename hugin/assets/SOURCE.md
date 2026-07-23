# Raven asset provenance

Requested source: <https://cdn.vectorstock.com/i/500p/12/14/raven-opened-its-wings-and-trampled-paws-vector-40631214.jpg>

The Raven artwork is an owner-provided-and-authorized project asset. The repository owner explicitly confirmed permission to retain, adapt, publish, and use it as HUGIN's visual identity.

Integrity is enforced through [`asset-manifest.json`](./asset-manifest.json), which records SHA-256 checksums for the original and every derived asset.

The CDN returned an automated "Access Restricted" placeholder during the build, so `raven-source.png` is the exact 500x500 reference image supplied by the user. `raven-source.jpg` is a JPEG compatibility copy of that reference.

`raven-mark.png`, `raven-red.png`, `raven-black.png`, and `favicon.png` are deterministic, non-generative derivatives produced by `scripts/process_raven_assets.py`. The process removes the gray background, separates the existing red and black artwork, completes the red disk behind the occluding raven for the boot animation, crops transparent padding, and creates the 32x32 favicon. The raven silhouette itself is not redrawn.
