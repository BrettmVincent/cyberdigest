// Lazily loads Natural Earth 110m country outlines (world-atlas) and projects them once.
// Loaded only when a map is shown, so the main bundle stays small.
import type { FeatureCollection, Geometry } from 'geojson';
import type { GeometryCollection, Topology } from 'topojson-specification';

export const MAP_W = 960;
export const MAP_H = 480;

export interface CountryShape {
  /** ISO 3166-1 numeric id (string, zero-padded). */
  id: string;
  name: string;
  d: string;
  centroid: [number, number];
}

let cache: Promise<CountryShape[]> | null = null;

export function loadWorld(): Promise<CountryShape[]> {
  cache ??= (async () => {
    const [{ feature }, { geoNaturalEarth1, geoPath }, atlas] = await Promise.all([
      import('topojson-client'),
      import('d3-geo'),
      import('world-atlas/countries-110m.json'),
    ]);
    const topo = atlas.default as unknown as Topology<{ countries: GeometryCollection<{ name: string }> }>;
    const fc = feature(topo, topo.objects.countries) as FeatureCollection<Geometry, { name: string }>;
    fc.features = fc.features.filter((f) => f.id !== '010'); // drop Antarctica
    const projection = geoNaturalEarth1().fitExtent(
      [
        [4, 4],
        [MAP_W - 4, MAP_H - 4],
      ],
      fc,
    );
    const path = geoPath(projection);
    return fc.features.map((f) => ({
      id: String(f.id ?? ''),
      name: f.properties?.name ?? '',
      d: path(f) ?? '',
      centroid: path.centroid(f),
    }));
  })();
  return cache;
}
