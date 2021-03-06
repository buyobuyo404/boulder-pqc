// Package trace gives access to direct control over the span and trace objects
// used by the beeline.
//
// Summary
//
// Elementary use of the Honeycomb beeline has few needs - use a wrapper to
// cover most of the basic info about a given event and then augment that event
// with a few fields using `beeline.AddField`. Occasionally add an additional
// span to the trace that is automatically created and add fields to that.
// However, as the beeline starts being used in more sophisticated applications,
// or new wrappers are being written, more direct control is needed to manipulate
// the spans and traces generated by the beeline.  Using the `trace` package
// enables this more sophisticated use.
//
// The types of use that are enabled by using the trace package:
//
// 1) creating asynchronous spans; spans that outlive the main trace. These spans
// are especially useful for goroutines that manage some background task after
// the main user-facing chore has been completed. Examples of this are sending
// an email or persisting accepted data.
//
// 2) creating traces with upstream parents when you are a downstream service.
// The existing HTTP wrappers do this for you, but if your trace is getting
// propagated via kafka or SQS or some other mechanism you may need to do this
// yourself
//
// 3) adding fields that use a different naming scheme. Fields added via the
// beeline are all namespaced under `app.`, which is convenient when you're
// adding a few. When you have more complicated code to manage, it can be
// useful to use your own naming scheme. Adding fields directly to the span or
// trace objects allows you to specify the full field name with no prefix.
//
// Lifecycle
//
// A trace is made up of spans. A span represents a single unit of work (what
// makes up a unit of work is up to the application). Spans come in two flavors,
// synchronous (the default) and asynchronous. Synchronous spans finish before
// their parents, async spans don't. Which you should use depends on the
// structure of code - if the outer function will block until the inner function
// returns, a sync span is appropriate. If the inner function is called in a
// goroutine and expected to outlive the outer function, an async span fits
// better.
//
// Spans should be created as children from an existing span. If there is no
// current span, first create a new trace then get its root span and use that to
// create subsequent spans. The beeline `StartSpan()` takes care of all of this
// for you, but if you're using the trace package directly you need to manage
// that bookkeeping.
//
// When should you create a new span? There are no strict rules, but there are a
// few heuristics. If there is a process that will repeat in a loop (a batch or
// something) and each run through the loop is important, make a span. If the
// code being instrumented has enough attributes that are relevant to it
// directly to warrant its own bag of data, make a new span. If all you're
// interested in is a simple timer, it's often cleaner to add that timer to the
// current existing span.
//
// Spans must have `Send()` called in order to be sent to Honeycomb. Every span
// that is created should have a corresponding `Send()` call. When `Send()` is
// called a few things happen. First, there is some trace-level accounting that
// is done (eg adding trace level fields, determining position in the trace,
// finishing the running timer, etc.). When that finishes the presend and
// sampler hooks are called. Finally, the span is dispatched to Honeycomb.
//
// Any span that calls out to another service can serialize the current state of
// the trace into a string suitable for including as an HTTP header (or other
// similar method for encoding as part of a message). That serialized form can
// be fed into the downstream service that will use it to start a new trace
// using the same trace ID. When you look at one of these traces in Honeycomb,
// you will see any spans created by the downstream service appear as children
// of the span that serialized its state. The serialized state includes the
// trace ID and the ID of the span that serialized state, as well as an encoded
// form of all trace level fields.
//
// Putting all this together, this is a visualization of a request that spawns
// two goroutines, each of which must return before the root span can return.
// Each of those also has a synchronous span as a child. One of those also kicks
// off an async span to save some state and it does not block returning the
// result to the original caller.
//
//    |----------- root span -----------|
//       \---- sync child ----|
//          \----|
//                      \------ async child ---------|
//       \--- sync child -------|
//            \-------------|
//
// Sampling
//
// The default sampling applied by the beeline samples entire traces. For
// example, if you set a sample rate to 10, then one out of 10 traces will be
// sent, and all spans in that trace will be sent (or none at all). If you take
// advantage of the SamplerHook, it is up to you and your implementation to
// decide whether to sample entire traces or individual spans. If traces are
// incomplete (i.e. some spans are kept and others dropped), the Honeycomb UI
// will show missing traces where there are children of dropped spans. Any
// dropped spans that have no children will be entirely absent from the UI.
//
// Use
//
// While easiest to use the `beeline` package and existing wrappers to do most
// of the legwork for you, here is the general flow of interaction with traces.
//
// - start of the request
//
// When a request starts or program execution begins, create a trace with
// `NewTrace`. If the program is downstream of something that is also traced,
// capture the serialized trace headers and pass them in to the trace creation
// to connect the two. The `NewTrace` function puts the trace and root span in
// the context for you.
//
// - during work
//
// As your program flows the most common pattern will be to start a span at the
// beginning of a function and then immediately defer sending that span.
//
//     func myFunc(ctx context.Context) {
//         ctx, span := beeline.StartSpan(ctx)                          // use the beeline if you can
//         // parentSpan := trace.GetSpanFromContext(ctx).CreateChild() // or do it manually
//         // not shown here - if you do it manually, check for nil to avoid panic
//         defer span.Send()
//         ...
//         span.AddField("app.fancy_feast_flavor", "pat??")
//         ...
//     }
//
// - wrapping up
//
// When each span finishes and gets sent, it also sends any synchronous
// children. Any synchronous spans that were unsent when their parent finished
// will get sent by the parent and will have an additional field
// (`meta.sent_by_parent`) added to indicate that they were unsent. Sending
// unsent spans is likely indicative of either an opportunity to use an async
// span or a bug in the program where a span accidentally does not get sent.
package trace
