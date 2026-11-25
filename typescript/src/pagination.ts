/** Cursor pagination. A list returns `rows` and an opaque `next` cursor; pass it back as `after` until `next` is null.
 * A page can hold fewer rows than the maximum while `next` is non-null, so always follow `next`. Never build or compare cursors. */
import type { Page } from './core.ts';

/** Yields every page, starting after `after` (a saved checkpoint) or from the beginning. */
export async function* paginate<Row>(fetchPage: (after: string | undefined) => Promise<Page<Row>>, after?: string): AsyncGenerator<Page<Row>> {
  const seen = new Set<string>();
  let cursor = after;
  for (;;) {
    const page = await fetchPage(cursor);
    yield page;
    if (page.next === null || page.next === undefined) return;
    if (seen.has(page.next)) throw new Error('PAGINATION_CURSOR_REPEATED');
    seen.add(page.next); cursor = page.next;
  }
}

/** Every row of every page, in order. */
export async function* rows<Row>(pages: AsyncIterable<Page<Row>>): AsyncGenerator<Row> {
  for await (const page of pages) yield* page.rows;
}
