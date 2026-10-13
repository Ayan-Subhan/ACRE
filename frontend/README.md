# ACRE frontend

3D results site for milestones M1–M4: an interactive architecture diagram (zones, segregation walls, live traffic) plus one page per component (Validator, Discriminator, IDS, Adversary, Base paper, Pipeline).

React 18 + Vite, three.js through React Three Fiber, ECharts for the charts, GSAP and Lenis for scrolling.

## Run

Node 22 is installed portably at `D:\nodejs` (it is not on PATH).

```bash
cd frontend
D:/nodejs/npm.cmd install
D:/nodejs/node.exe node_modules/vite/bin/vite.js        # dev server on http://localhost:5173
D:/nodejs/node.exe node_modules/vite/bin/vite.js build  # static build in dist/
```

## Data

The charts read `public/data/*.json`. These files are generated from `aad/artifacts/reports` and are not edited by hand. Re-export them after any new run:

```bash
python aad/scripts/export_frontend_data.py
```

The base-paper numbers come from `aad/docs/basepaper_results.json`. They were transcribed from Verma et al. (IEEE TCE 2025), Table III and Figs. 3–9.

## Icons

`public/icons/` holds the three original icons from `frontend_svg/` with their ids namespaced, plus generated ones in the same isometric style. To regenerate:

```bash
python frontend/tools/make_icons.py
```

The generator also copies the new icons back into `frontend_svg/`.

## Deploy (free, static)

The build is a static site in `dist/`. `public/_redirects` sends every route to `index.html`, so links like `/validator` work when opened directly.

- **Netlify**: Add new site → Import from Git → `Ayan-Subhan/ACRE`. Set Base directory to `frontend`. `netlify.toml` supplies the build command (`npm run build`), the publish directory (`dist`) and Node 22.
- **Cloudflare Pages**: Create → Pages → Connect to Git → `Ayan-Subhan/ACRE`. Choose the Vite preset, Root directory `frontend`, build command `npm run build`, output `dist`. `.nvmrc` pins Node 22.

Every push to `main` redeploys. Re-export the data before pushing new results.
