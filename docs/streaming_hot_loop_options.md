# Options to Avoid Hot Loop Polling in HTTP Streaming

## Problem Statement

The current input stream API requires the connection thread to continuously poll for data availability, even when no data is ready. This "hot loop" polling consumes CPU resources unnecessarily and impacts performance.

## Current Approaches

### 1. Input Stream API (Current Implementation)

**Pros:**
* Zero-copy design - customer writes directly into CRT-owned buffer
* No intermediate buffer required
* Maximum efficiency when data is available

**Cons:**
* Connection thread must continuously poll even when no data is available
* Wastes CPU cycles in hot loop
* Poor performance when data arrival is sporadic

### 2. write_data API

**Pros:**
* User provides data only when available
* Avoids continuous polling

**Cons:**
* Difficult to provide multiple different input streams without intermediate buffer (extra copy)
* Does not support HTTP/1.1 with Content-Length (existing limitation)
* May require buffering to merge multiple streams

## What CURL Does

### Pause/Resume Mechanism

CURL's `CURLOPT_READFUNCTION` callback allows returning `CURL_READFUNC_PAUSE` to stop polling. The connection can be resumed later via `curl_easy_pause()` when data becomes available.

**Key insight:** Application controls when to pause/resume based on data availability.

## CRT and SDK, what should we do?

### Option A: Application-Controlled Pause/Resume with InputStream API

```c
// Pseudo-API
aws_http_stream_pause_polling(stream);
aws_http_stream_resume_polling(stream);
```

**Implementation approach:**
* Input stream callback can signal "no data available"
* CRT stops polling until explicitly resumed
* Application resumes when data becomes ready

**SDK implications:**
* SDKs to expose pause/resume to applications OR
* SDKs to manage pause/resume internally somehow (without buffering if possible)

**Trade-offs:**
* ✅ Eliminates hot loop when no data available
* ✅ Maintains zero-copy when data flows
* ❌ Adds complexity - someone must track data availability
* ❌ SDKs may need buffering layer to shield users from complexity

#### Option B: Stick with write_data API

Enhance `write_data` API to support:
* HTTP/1.1 Content-Length specification
* Direct writes to CRT buffer when possible

**Trade-offs:**
* ✅ Leverages existing API pattern
* ✅ Avoids polling altogether
* ❌ Maybe hard to write directly to CRT buffer
* ❌ Still polling for the input stream provided, SDK will need to make sure the provided input stream to be available.
