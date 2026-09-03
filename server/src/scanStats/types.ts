// One slice of a chart on the Scan Stats page. Every aggregation there
// returns this same shape so a single DonutChart renders all of them.
export interface Slice {
  label: string;
  value: number;
}
