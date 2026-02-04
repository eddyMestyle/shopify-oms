import { type NextRequest, NextResponse } from 'next/server'
import { AppError, ErrorCodes, handleApiError, logger } from '@/lib/utils/errors'
import { env, graphqlQuerySchema } from '@/lib/utils/validation'
import type { ShopifyGraphQLResponse } from '@/types/shopify'

// List of sensitive fields to completely remove from API response
const SENSITIVE_FIELDS = new Set([
  'email',
  'phone',
  'firstname',
  'lastname',
  'displayname',
  'address1',
  'address2',
  'company',
])

// Fields to remove only when inside address context
const ADDRESS_NAME_FIELD = 'name'

// Recursively remove sensitive fields from response data
function removeSensitiveData(obj: unknown): unknown {
  if (obj === null || obj === undefined) return obj
  if (Array.isArray(obj)) return obj.map(removeSensitiveData)
  if (typeof obj !== 'object') return obj

  const record = obj as Record<string, unknown>
  const cleaned: Record<string, unknown> = {}

  // Check if this object is an address context
  const siblingKeys = Object.keys(record).map((k) => k.toLowerCase())
  const isAddressContext = siblingKeys.some((k) =>
    ['address1', 'address2', 'city', 'province', 'zip', 'country'].includes(k)
  )

  for (const [key, value] of Object.entries(record)) {
    const lowerKey = key.toLowerCase()

    // Skip sensitive fields entirely
    if (SENSITIVE_FIELDS.has(lowerKey)) {
      continue
    }

    // Skip name field only in address context (but keep order name like #1234)
    if (
      lowerKey === ADDRESS_NAME_FIELD &&
      typeof value === 'string' &&
      !value.startsWith('#') &&
      isAddressContext
    ) {
      continue
    }

    // Recursively process nested objects
    if (typeof value === 'object') {
      cleaned[key] = removeSensitiveData(value)
    } else {
      cleaned[key] = value
    }
  }

  return cleaned
}

// CORS headers configuration
const corsHeaders = {
  'Access-Control-Allow-Origin': env.NEXT_PUBLIC_ALLOWED_ORIGINS || '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
}

// Rate limiting map (simple in-memory implementation)
// In production, use Redis or similar
const rateLimitMap = new Map<string, { count: number; resetTime: number }>()

const RATE_LIMIT_WINDOW = 60 * 1000 // 1 minute
const RATE_LIMIT_MAX = 30 // 30 requests per minute

function checkRateLimit(identifier: string): boolean {
  const now = Date.now()
  const limit = rateLimitMap.get(identifier)

  if (!limit || now > limit.resetTime) {
    rateLimitMap.set(identifier, {
      count: 1,
      resetTime: now + RATE_LIMIT_WINDOW,
    })
    return true
  }

  if (limit.count >= RATE_LIMIT_MAX) {
    return false
  }

  limit.count++
  return true
}

export function OPTIONS() {
  return new Response(null, {
    status: 200,
    headers: corsHeaders,
  })
}

export async function POST(request: NextRequest) {
  try {
    // Get client identifier for rate limiting
    const clientIp =
      request.headers.get('x-forwarded-for') || request.headers.get('x-real-ip') || 'unknown'

    // Check rate limit
    if (!checkRateLimit(clientIp)) {
      throw new AppError(
        'Too many requests. Please try again later.',
        ErrorCodes.RATE_LIMIT_EXCEEDED,
        429
      )
    }

    // Validate environment variables at runtime
    const storeDomain = env.SHOPIFY_STORE_DOMAIN || process.env.SHOPIFY_STORE_DOMAIN
    const accessToken = env.SHOPIFY_ADMIN_ACCESS_TOKEN || process.env.SHOPIFY_ADMIN_ACCESS_TOKEN

    if (!storeDomain || !accessToken) {
      logger.error('Missing Shopify configuration', {
        hasStoreDomain: Boolean(storeDomain),
        hasAccessToken: Boolean(accessToken),
      })

      throw new AppError('Server configuration error', ErrorCodes.INTERNAL_SERVER_ERROR, 500)
    }

    // Parse and validate request body
    const body = await request.json()
    const validationResult = graphqlQuerySchema.safeParse(body)

    if (!validationResult.success) {
      throw new AppError('Invalid request format', ErrorCodes.VALIDATION_ERROR, 400)
    }

    const { query, variables } = validationResult.data

    // Log the incoming request (without sensitive data)
    logger.info('Shopify API request', {
      clientIp,
      queryLength: query.length,
      hasVariables: Boolean(variables),
    })

    // Create Shopify GraphQL endpoint URL
    const shopifyUrl = `https://${storeDomain}/admin/api/2024-07/graphql.json`

    // Call Shopify Admin API
    const shopifyRequest = await fetch(shopifyUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Shopify-Access-Token': accessToken,
      },
      body: JSON.stringify({ query, variables }),
    })

    if (!shopifyRequest.ok) {
      const errorText = await shopifyRequest.text()
      logger.error('Shopify API Error', {
        status: shopifyRequest.status,
        statusText: shopifyRequest.statusText,
        error: errorText,
      })

      throw new AppError(
        'Failed to communicate with Shopify',
        ErrorCodes.BAD_REQUEST,
        shopifyRequest.status
      )
    }

    const shopifyData = (await shopifyRequest.json()) as ShopifyGraphQLResponse

    // Check for GraphQL errors
    if (shopifyData.errors) {
      logger.warn('Shopify GraphQL Errors', {
        errors: shopifyData.errors,
      })

      return NextResponse.json(
        {
          error: 'GraphQL errors occurred',
          code: ErrorCodes.BAD_REQUEST,
          details: shopifyData.errors,
        },
        {
          status: 400,
          headers: corsHeaders,
        }
      )
    }

    // Remove sensitive customer data before returning to client
    const cleanedData = removeSensitiveData(shopifyData)

    // Return successful response with cleaned data
    return NextResponse.json(cleanedData, {
      headers: corsHeaders,
    })
  } catch (error) {
    return handleApiError(error)
  }
}

// Only allow POST and OPTIONS methods
export function GET() {
  return NextResponse.json(
    {
      error: 'Method Not Allowed. Use POST instead.',
      code: ErrorCodes.BAD_REQUEST,
    },
    { status: 405 }
  )
}
