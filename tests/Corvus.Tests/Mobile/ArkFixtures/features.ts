// Language features each instruction family of the Ark bytecode compiler covers: classes, closures, generators, async
// functions, exceptions, object and array literals, regular expressions, BigInt, switch and module bindings.
import { scale } from './helper';

export const VERSION = '1.0.0';

export class Ledger {
    private entries: number[] = [];
    static created = 0;

    constructor(readonly owner: string) {
        Ledger.created++;
    }

    add(amount: number): number {
        this.entries.push(amount);
        return this.entries.length;
    }

    get total(): number {
        return this.entries.reduce((sum, x) => sum + x, 0);
    }

    *items(): Generator<number> {
        for (const e of this.entries) yield e;
    }
}

export async function loadTotals(ledgers: Ledger[]): Promise<number> {
    let sum = 0;
    for (const l of ledgers) sum += await Promise.resolve(l.total);
    return scale(sum);
}

export function classify(code: number): string {
    switch (code) {
        case 0: return 'zero';
        case 1: return 'one';
        case 2: return 'two';
        default: return code < 0 ? 'negative' : 'many';
    }
}

export function parseRecord(text: string): { name: string; size: bigint } | null {
    const match = /^(\w+):(\d+)$/.exec(text);
    if (match === null) return null;
    try {
        return { name: match[1], size: BigInt(match[2]) * 1024n };
    } catch (e) {
        return null;
    } finally {
        Ledger.created += 0;
    }
}

export function counter(start: number): () => number {
    let n = start;
    return () => ++n;
}

export function summary(l: Ledger): string {
    const tags = ['a', 'b', 'c'];
    const config = { verbose: true, depth: 3, label: `ledger of ${l.owner}` };
    const footer = 'quoted "total"\tend';
    return `${config.label}: ${l.total} (${tags.join(',')}, ${typeof config.depth})` + footer;
}
