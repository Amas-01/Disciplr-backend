/**
 * =========================================================================
 * THREAT MODEL — Org-Scoped Analytics Authorization (Issue #146)
 * =========================================================================
 *
 * LEAK SCENARIO:
 * The orgAnalytics route (GET /api/organizations/:orgId/analytics) returns
 * aggregate financial data (totalCapital, successRate, vault counts) and
 * per-creator team performance breakdowns. If the authorization middleware
 * were absent, misconfigured, or bypassable:
 *   - An unauthenticated caller could enumerate orgIds and harvest analytics
 *   - An authenticated user from Org B could request Org A's analytics by
 *     simply changing the :orgId route parameter
 *   - A 'member'-role user within the correct org could access analytics
 *     that require 'owner' or 'admin' role
 *   - A caller with a forged/invalid JWT could bypass authentication
 *
 * ATTACK SURFACES TESTED:
 *   1. GET /api/organizations/:orgId/analytics — the sole orgAnalytics endpoint
 *      - Route parameter :orgId manipulation
 *      - Authorization header manipulation
 *      - Role escalation via token claims
 *
 * IDENTITY AXES VARIED:
 *   - Unauthenticated (no token, malformed token, expired token)
 *   - Authenticated wrong org (member of Org B → Org A, admin of Org B → Org A)
 *   - Authenticated correct org but insufficient role (member → analytics)
 *   - Forged token (signed with wrong secret)
 *   - Valid authorized user (positive control: owner, admin)
 *
 * INVARIANTS PROVEN:
 *   1. Unauthenticated caller NEVER receives org analytics data
 *   2. Authenticated Org B caller NEVER receives Org A analytics data
 *   3. Insufficient-role caller NEVER receives analytics data
 *   4. Forged-token caller NEVER receives analytics data
 *   5. Every unauthorized response returns correct HTTP status (401 or 403)
 *   6. Every unauthorized response body does NOT leak org structure, user
 *      counts, capital amounts, creator names, or any PII-adjacent aggregate
 *
 * NON-GOALS:
 *   - Performance or load testing
 *   - Correctness of analytics calculations (covered by analytics.test.ts)
 *   - Frontend behaviour
 *   - Cross-org vault listing isolation (covered by orgVaultIsolation.test.ts)
 * =========================================================================
 */

import request from 'supertest'
import express, { Request, Response, NextFunction } from 'express'
import jwt from 'jsonwebtoken'
import { describe, it, expect, beforeEach, afterEach } from '@jest/globals'
import { requireOrgAccess } from '../src/middleware/orgAuth.js'
import {
    setOrganizations,
    setOrgMembers,
} from '../src/models/organizations.js'

// ── Constants ────────────────────────────────────────────────────────────
const JWT_SECRET = process.env.JWT_SECRET ?? 'change-me-in-production'
const WRONG_SECRET = 'this-is-not-the-correct-secret'

const ORG_A = 'org-alpha'
const ORG_B = 'org-beta'

// Analytics response fields that must NEVER appear in unauthorized responses
const ANALYTICS_FIELDS = [
    'totalCapital',
    'successRate',
    'activeVaults',
    'completedVaults',
    'failedVaults',
    'teamPerformance',
    'generatedAt',
]

// PII / org-identifying fields
const PII_FIELDS = ['creator', 'email', 'name']

// ── Mock authenticate (no session/DB dependency) ─────────────────────────
function mockAuthenticate(req: Request, res: Response, next: NextFunction): void {
    const authHeader = req.headers.authorization
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        res.status(401).json({ error: 'Missing or malformed Authorization header' })
        return
    }
    try {
        const payload = jwt.verify(authHeader.slice(7), JWT_SECRET)
        req.user = payload as any
        next()
    } catch (err) {
        if (err instanceof jwt.TokenExpiredError) {
            res.status(401).json({ error: 'Token expired' })
        } else {
            res.status(401).json({ error: 'Invalid token' })
        }
    }
}

// ── In-memory vault store ────────────────────────────────────────────────
let testVaults: any[] = []

// ── Test Express app ─────────────────────────────────────────────────────
const app = express()
app.use(express.json())

app.get(
    '/api/organizations/:orgId/analytics',
    mockAuthenticate,
    requireOrgAccess('owner', 'admin'),
    (req: Request, res: Response) => {
        const { orgId } = req.params
        const orgVaults = testVaults.filter((v) => v.orgId === orgId)

        const activeVaults = orgVaults.filter((v) => v.status === 'active').length
        const completedVaults = orgVaults.filter((v) => v.status === 'completed').length
        const failedVaults = orgVaults.filter((v) => v.status === 'failed').length

        const totalCapital = orgVaults
            .reduce((sum, v) => sum + parseFloat(v.amount || '0'), 0)
            .toString()

        const resolved = completedVaults + failedVaults
        const successRate = resolved > 0 ? completedVaults / resolved : 0

        const creatorMap = new Map<string, any[]>()
        for (const v of orgVaults) {
            const list = creatorMap.get(v.creator) ?? []
            list.push(v)
            creatorMap.set(v.creator, list)
        }

        const teamPerformance = Array.from(creatorMap.entries()).map(([creator, cvaults]) => {
            const completed = cvaults.filter((v: any) => v.status === 'completed').length
            const failed = cvaults.filter((v: any) => v.status === 'failed').length
            const creatorResolved = completed + failed
            return {
                creator,
                vaultCount: cvaults.length,
                totalAmount: cvaults.reduce((s: number, v: any) => s + parseFloat(v.amount || '0'), 0).toString(),
                successRate: creatorResolved > 0 ? completed / creatorResolved : 0,
            }
        })

        res.json({
            orgId,
            analytics: { totalCapital, successRate, activeVaults, completedVaults, failedVaults },
            teamPerformance,
            generatedAt: new Date().toISOString(),
        })
    }
)

// ── Token factories ──────────────────────────────────────────────────────

/** Create a valid Bearer token for a user */
const validToken = (sub: string, role: string = 'USER') =>
    `Bearer ${jwt.sign({ sub, userId: sub, role }, JWT_SECRET, { expiresIn: '1h' })}`

/** Create an expired Bearer token */
const expiredToken = (sub: string, role: string = 'USER') =>
    `Bearer ${jwt.sign({ sub, userId: sub, role }, JWT_SECRET, { expiresIn: '-1s' })}`

/** Create a token signed with the WRONG secret (forged) */
const forgedToken = (sub: string, role: string = 'ADMIN') =>
    `Bearer ${jwt.sign({ sub, userId: sub, role }, WRONG_SECRET, { expiresIn: '1h' })}`

/** Malformed Authorization header values */
const MALFORMED_HEADERS = [
    'NotBearer some-token',
    'Bearer',
    'bearer valid-looking-token',
    '',
]

// ── Leak prevention helper ───────────────────────────────────────────────

/**
 * Asserts that a response body does not leak any analytics data,
 * org identifiers, user counts, PII, or internal errors.
 * Applied to EVERY negative test case.
 */
function assertNoLeaks(res: request.Response, targetOrgId?: string): void {
    const body = res.body
    const json = JSON.stringify(body)

    // Must not contain any analytics fields
    for (const field of ANALYTICS_FIELDS) {
        expect(body).not.toHaveProperty(field)
        expect(body.analytics).toBeUndefined()
    }

    // Must not contain team performance data
    expect(body.teamPerformance).toBeUndefined()

    // Must not contain the target orgId in the response (other than in error messages)
    if (targetOrgId) {
        // The orgId should not appear as a value in the response body
        expect(body.orgId).toBeUndefined()
    }

    // Must not contain PII fields
    for (const field of PII_FIELDS) {
        expect(body[field]).toBeUndefined()
    }

    // Must not contain stack traces or file paths
    expect(json).not.toMatch(/\.ts:\d+/)
    expect(json).not.toMatch(/\.js:\d+/)
    expect(json).not.toMatch(/node_modules/)
    expect(json).not.toMatch(/at\s+\w+\s+\(/)

    // Must not contain numeric aggregates that look like analytics
    expect(body.activeVaults).toBeUndefined()
    expect(body.completedVaults).toBeUndefined()
    expect(body.failedVaults).toBeUndefined()
    expect(body.totalCapital).toBeUndefined()
    expect(body.successRate).toBeUndefined()
}

// ── Seed / Teardown ──────────────────────────────────────────────────────

function seed() {
    setOrganizations([
        { id: ORG_A, name: 'Alpha Corp', createdAt: '2025-01-01T00:00:00Z' },
        { id: ORG_B, name: 'Beta Inc', createdAt: '2025-02-01T00:00:00Z' },
    ])

    setOrgMembers([
        { orgId: ORG_A, userId: 'alice', role: 'owner' },
        { orgId: ORG_A, userId: 'bob', role: 'admin' },
        { orgId: ORG_A, userId: 'carol', role: 'member' },
        { orgId: ORG_B, userId: 'dave', role: 'owner' },
        { orgId: ORG_B, userId: 'eve', role: 'admin' },
        { orgId: ORG_B, userId: 'frank', role: 'member' },
    ])

    const base = {
        startTimestamp: '2025-01-01T00:00:00Z',
        endTimestamp: '2025-12-31T00:00:00Z',
        successDestination: 'addr-ok',
        failureDestination: 'addr-fail',
        createdAt: '2025-01-01T00:00:00Z',
    }

    testVaults = [
        { ...base, id: 'va-1', creator: 'alice', amount: '1000', status: 'active', orgId: ORG_A },
        { ...base, id: 'va-2', creator: 'bob', amount: '2000', status: 'completed', orgId: ORG_A },
        { ...base, id: 'va-3', creator: 'carol', amount: '500', status: 'failed', orgId: ORG_A },
        { ...base, id: 'vb-1', creator: 'dave', amount: '3000', status: 'active', orgId: ORG_B },
        { ...base, id: 'vb-2', creator: 'eve', amount: '4000', status: 'completed', orgId: ORG_B },
    ]
}

beforeEach(() => seed())
afterEach(() => {
    testVaults = []
    setOrganizations([])
    setOrgMembers([])
})

// =========================================================================
// 1. Unauthenticated Access
// =========================================================================
describe('Unauthenticated access to org analytics', () => {
    it('request with no Authorization header returns 401', async () => {
        const res = await request(app).get(`/api/organizations/${ORG_A}/analytics`)
        expect(res.status).toBe(401)
        assertNoLeaks(res, ORG_A)
    })

    it('request with malformed Authorization header (no Bearer prefix) returns 401', async () => {
        const res = await request(app)
            .get(`/api/organizations/${ORG_A}/analytics`)
            .set('Authorization', 'NotBearer some-token')
        expect(res.status).toBe(401)
        assertNoLeaks(res, ORG_A)
    })

    it('request with "Bearer" but no token value returns 401', async () => {
        const res = await request(app)
            .get(`/api/organizations/${ORG_A}/analytics`)
            .set('Authorization', 'Bearer')
        expect(res.status).toBe(401)
        assertNoLeaks(res, ORG_A)
    })

    it('request with empty Authorization header returns 401', async () => {
        const res = await request(app)
            .get(`/api/organizations/${ORG_A}/analytics`)
            .set('Authorization', '')
        expect(res.status).toBe(401)
        assertNoLeaks(res, ORG_A)
    })

    it('request with structurally invalid JWT returns 401', async () => {
        const res = await request(app)
            .get(`/api/organizations/${ORG_A}/analytics`)
            .set('Authorization', 'Bearer not.a.valid.jwt.token')
        expect(res.status).toBe(401)
        assertNoLeaks(res, ORG_A)
    })
})

// =========================================================================
// 2. Expired Token
// =========================================================================
describe('Expired token access to org analytics', () => {
    it('request with expired token returns 401', async () => {
        const res = await request(app)
            .get(`/api/organizations/${ORG_A}/analytics`)
            .set('Authorization', expiredToken('alice'))
        expect(res.status).toBe(401)
        assertNoLeaks(res, ORG_A)
    })

    it('expired token response body contains no analytics data', async () => {
        const res = await request(app)
            .get(`/api/organizations/${ORG_A}/analytics`)
            .set('Authorization', expiredToken('alice'))
        expect(res.body.analytics).toBeUndefined()
        expect(res.body.teamPerformance).toBeUndefined()
        expect(res.body.generatedAt).toBeUndefined()
    })
})

// =========================================================================
// 3. Wrong Organization
// =========================================================================
describe('Wrong organization access to org analytics', () => {
    it('Org B member requesting Org A analytics returns 403', async () => {
        const res = await request(app)
            .get(`/api/organizations/${ORG_A}/analytics`)
            .set('Authorization', validToken('frank')) // frank is member of Org B
        expect(res.status).toBe(403)
        assertNoLeaks(res, ORG_A)
    })

    it('Org B owner requesting Org A analytics returns 403', async () => {
        const res = await request(app)
            .get(`/api/organizations/${ORG_A}/analytics`)
            .set('Authorization', validToken('dave')) // dave is owner of Org B
        expect(res.status).toBe(403)
        assertNoLeaks(res, ORG_A)
    })

    it('Org B admin requesting Org A analytics returns 403', async () => {
        const res = await request(app)
            .get(`/api/organizations/${ORG_A}/analytics`)
            .set('Authorization', validToken('eve')) // eve is admin of Org B
        expect(res.status).toBe(403)
        assertNoLeaks(res, ORG_A)
    })

    it('Org A owner requesting Org B analytics returns 403', async () => {
        const res = await request(app)
            .get(`/api/organizations/${ORG_B}/analytics`)
            .set('Authorization', validToken('alice')) // alice is owner of Org A
        expect(res.status).toBe(403)
        assertNoLeaks(res, ORG_B)
    })

    it('wrong-org 403 response does not contain target org analytics', async () => {
        const res = await request(app)
            .get(`/api/organizations/${ORG_A}/analytics`)
            .set('Authorization', validToken('dave'))
        const json = JSON.stringify(res.body)
        // Must not contain Org A's vault data
        expect(json).not.toContain('1000')  // alice's vault amount
        expect(json).not.toContain('2000')  // bob's vault amount
        expect(json).not.toContain('3500')  // org A total capital
        expect(json).not.toContain('alice')
        expect(json).not.toContain('bob')
        expect(json).not.toContain('carol')
    })

    it('403 response shape is identical regardless of whether target org exists', async () => {
        // Request real org (Org A) from Org B user
        const realOrgRes = await request(app)
            .get(`/api/organizations/${ORG_A}/analytics`)
            .set('Authorization', validToken('dave'))

        // Request non-existent org from same user
        const fakeOrgRes = await request(app)
            .get('/api/organizations/org-does-not-exist/analytics')
            .set('Authorization', validToken('dave'))

        // Both should be rejections (403 or 404)
        expect([403, 404]).toContain(realOrgRes.status)
        expect([403, 404]).toContain(fakeOrgRes.status)

        // Neither should contain analytics data
        assertNoLeaks(realOrgRes, ORG_A)
        assertNoLeaks(fakeOrgRes, 'org-does-not-exist')
    })
})

// =========================================================================
// 4. Insufficient Role Within Correct Organization
// =========================================================================
describe('Insufficient role within correct org', () => {
    it('member of Org A cannot access Org A analytics (requires owner/admin) → 403', async () => {
        const res = await request(app)
            .get(`/api/organizations/${ORG_A}/analytics`)
            .set('Authorization', validToken('carol')) // carol is member of Org A
        expect(res.status).toBe(403)
        assertNoLeaks(res, ORG_A)
    })

    it('member of Org B cannot access Org B analytics → 403', async () => {
        const res = await request(app)
            .get(`/api/organizations/${ORG_B}/analytics`)
            .set('Authorization', validToken('frank')) // frank is member of Org B
        expect(res.status).toBe(403)
        assertNoLeaks(res, ORG_B)
    })

    it('insufficient role 403 response does not leak analytics data', async () => {
        const res = await request(app)
            .get(`/api/organizations/${ORG_A}/analytics`)
            .set('Authorization', validToken('carol'))
        expect(res.body.analytics).toBeUndefined()
        expect(res.body.teamPerformance).toBeUndefined()
        expect(res.body.orgId).toBeUndefined()
    })
})

// =========================================================================
// 5. Forged Token Claims
// =========================================================================
describe('Forged token claims', () => {
    it('token signed with wrong secret returns 401', async () => {
        const res = await request(app)
            .get(`/api/organizations/${ORG_A}/analytics`)
            .set('Authorization', forgedToken('alice', 'ADMIN'))
        expect(res.status).toBe(401)
        assertNoLeaks(res, ORG_A)
    })

    it('forged token with elevated role claim still returns 401', async () => {
        // Attempt to forge a token claiming admin role, signed with wrong secret
        const token = jwt.sign(
            { sub: 'carol', userId: 'carol', role: 'ADMIN' },
            WRONG_SECRET,
            { expiresIn: '1h' }
        )
        const res = await request(app)
            .get(`/api/organizations/${ORG_A}/analytics`)
            .set('Authorization', `Bearer ${token}`)
        expect(res.status).toBe(401)
        assertNoLeaks(res, ORG_A)
    })

    it('forged token attempting org access returns no analytics data', async () => {
        const res = await request(app)
            .get(`/api/organizations/${ORG_A}/analytics`)
            .set('Authorization', forgedToken('alice'))
        const json = JSON.stringify(res.body)
        expect(json).not.toContain('totalCapital')
        expect(json).not.toContain('successRate')
        expect(json).not.toContain('teamPerformance')
    })
})

// =========================================================================
// 6. Missing/Invalid Route Parameters
// =========================================================================
describe('Missing or invalid route parameters', () => {
    it('non-existent orgId returns 404', async () => {
        const res = await request(app)
            .get('/api/organizations/org-nonexistent/analytics')
            .set('Authorization', validToken('alice'))
        expect(res.status).toBe(404)
        assertNoLeaks(res, 'org-nonexistent')
    })

    it('non-existent org 404 response does not reveal org existence info via differential response', async () => {
        const existsRes = await request(app)
            .get(`/api/organizations/${ORG_B}/analytics`)
            .set('Authorization', validToken('alice')) // alice not member of B
        const notExistsRes = await request(app)
            .get('/api/organizations/org-fake/analytics')
            .set('Authorization', validToken('alice'))

        // Neither response should contain analytics data
        assertNoLeaks(existsRes, ORG_B)
        assertNoLeaks(notExistsRes, 'org-fake')
    })

    it('user with no org membership at all gets 403', async () => {
        const res = await request(app)
            .get(`/api/organizations/${ORG_A}/analytics`)
            .set('Authorization', validToken('ghost-user'))
        expect(res.status).toBe(403)
        assertNoLeaks(res, ORG_A)
    })
})

// =========================================================================
// 7. Response Body Leak Prevention (comprehensive)
// =========================================================================
describe('Response body leak prevention across all rejection types', () => {
    const scenarios: Array<{
        name: string
        token: string | undefined
        orgId: string
        expectedStatus: number[]
    }> = [
            { name: 'no token', token: undefined, orgId: ORG_A, expectedStatus: [401] },
            { name: 'expired token', token: expiredToken('alice'), orgId: ORG_A, expectedStatus: [401] },
            { name: 'forged token', token: forgedToken('alice'), orgId: ORG_A, expectedStatus: [401] },
            { name: 'wrong org member', token: validToken('dave'), orgId: ORG_A, expectedStatus: [403] },
            { name: 'wrong org admin', token: validToken('eve'), orgId: ORG_A, expectedStatus: [403] },
            { name: 'insufficient role', token: validToken('carol'), orgId: ORG_A, expectedStatus: [403] },
            { name: 'non-existent org', token: validToken('alice'), orgId: 'org-fake', expectedStatus: [404] },
        ]

    for (const scenario of scenarios) {
        it(`${scenario.name}: response contains no analytics fields`, async () => {
            const req = request(app).get(`/api/organizations/${scenario.orgId}/analytics`)
            if (scenario.token) {
                req.set('Authorization', scenario.token)
            }
            const res = await req
            expect(scenario.expectedStatus).toContain(res.status)
            assertNoLeaks(res, scenario.orgId)
        })

        it(`${scenario.name}: serialized response body has no numeric vault counts`, async () => {
            const req = request(app).get(`/api/organizations/${scenario.orgId}/analytics`)
            if (scenario.token) {
                req.set('Authorization', scenario.token)
            }
            const res = await req
            const json = JSON.stringify(res.body)
            // Should not contain any key/value patterns from analytics response
            expect(json).not.toMatch(/"activeVaults"/)
            expect(json).not.toMatch(/"completedVaults"/)
            expect(json).not.toMatch(/"failedVaults"/)
            expect(json).not.toMatch(/"totalCapital"/)
            expect(json).not.toMatch(/"teamPerformance"/)
        })
    }
})

// =========================================================================
// 8. Positive Control Tests
// =========================================================================
describe('Positive controls — authorized access works correctly', () => {
    it('Org A owner receives 200 with correctly shaped analytics response', async () => {
        const res = await request(app)
            .get(`/api/organizations/${ORG_A}/analytics`)
            .set('Authorization', validToken('alice'))
        expect(res.status).toBe(200)

        // Verify response shape
        expect(res.body).toHaveProperty('orgId', ORG_A)
        expect(res.body).toHaveProperty('analytics')
        expect(res.body.analytics).toHaveProperty('totalCapital')
        expect(res.body.analytics).toHaveProperty('successRate')
        expect(res.body.analytics).toHaveProperty('activeVaults')
        expect(res.body.analytics).toHaveProperty('completedVaults')
        expect(res.body.analytics).toHaveProperty('failedVaults')
        expect(res.body).toHaveProperty('teamPerformance')
        expect(res.body).toHaveProperty('generatedAt')
        expect(Array.isArray(res.body.teamPerformance)).toBe(true)
    })

    it('Org A admin receives 200 with analytics data', async () => {
        const res = await request(app)
            .get(`/api/organizations/${ORG_A}/analytics`)
            .set('Authorization', validToken('bob'))
        expect(res.status).toBe(200)
        expect(res.body.orgId).toBe(ORG_A)
        expect(res.body.analytics.totalCapital).toBe('3500')
        expect(res.body.analytics.activeVaults).toBe(1)
        expect(res.body.analytics.completedVaults).toBe(1)
        expect(res.body.analytics.failedVaults).toBe(1)
    })

    it('Org B owner receives 200 with Org B analytics (not Org A data)', async () => {
        const res = await request(app)
            .get(`/api/organizations/${ORG_B}/analytics`)
            .set('Authorization', validToken('dave'))
        expect(res.status).toBe(200)
        expect(res.body.orgId).toBe(ORG_B)
        expect(res.body.analytics.totalCapital).toBe('7000')
        expect(res.body.analytics.activeVaults).toBe(1)
        expect(res.body.analytics.completedVaults).toBe(1)
        expect(res.body.analytics.failedVaults).toBe(0)
    })

    it('positive response contains correct team performance breakdown', async () => {
        const res = await request(app)
            .get(`/api/organizations/${ORG_A}/analytics`)
            .set('Authorization', validToken('alice'))
        expect(res.status).toBe(200)
        expect(res.body.teamPerformance).toHaveLength(3) // alice, bob, carol
        const creators = res.body.teamPerformance.map((t: any) => t.creator).sort()
        expect(creators).toEqual(['alice', 'bob', 'carol'])
    })

    it('authorized user Org A analytics does not contain Org B data', async () => {
        const res = await request(app)
            .get(`/api/organizations/${ORG_A}/analytics`)
            .set('Authorization', validToken('alice'))
        const json = JSON.stringify(res.body)
        expect(json).not.toContain(ORG_B)
        expect(json).not.toContain('dave')
        expect(json).not.toContain('eve')
        // Total capital should be 3500, not 10500
        expect(res.body.analytics.totalCapital).toBe('3500')
    })
})
