// Copyright © 2021-present 650 Industries, Inc. (aka Expo)

#pragma once

#include "JNIDeallocator.h"

#include <jsi/jsi.h>
#include <fbjni/fbjni.h>
#include <ReactCommon/CallInvoker.h>

namespace jsi = facebook::jsi;
namespace jni = facebook::jni;
namespace react = facebook::react;

namespace expo {

class JavaScriptValue;
class JavaScriptObject;
class JSIInteropModuleRegistry;

#if REACT_NATIVE_TARGET_VERSION >= 73
using NativeMethodCallInvokerCompatible = react::NativeMethodCallInvoker;
#else
using NativeMethodCallInvokerCompatible = react::CallInvoker;
#endif

/**
 * A wrapper for the jsi::Runtime.
 * This class is used as a bridge between CPP and Kotlin and to encapsulate common runtime helper functions.
 *
 * Instances of this class should be managed using a shared smart pointer.
 * To pass runtime information to all of `JavaScriptValue` and `JavaScriptObject` we use `weak_from_this()`
 * that requires that the object is held via a smart pointer. Otherwise, `weak_from_this()` returns `nullptr`.
 */
class JavaScriptRuntime : public std::enable_shared_from_this<JavaScriptRuntime> {
public:
  /**
   * Initializes a runtime that is independent from React Native and its runtime initialization.
   * This flow is mostly intended for tests. The JS call invoker is set to `SyncCallInvoker`.
   * See **JavaScriptRuntime.cpp** for the `SyncCallInvoker` implementation.
   */
  JavaScriptRuntime(
    JSIInteropModuleRegistry *jsiInteropModuleRegistry
  );

  JavaScriptRuntime(
    JSIInteropModuleRegistry *jsiInteropModuleRegistry,
    jsi::Runtime *runtime,
    std::shared_ptr<react::CallInvoker> jsInvoker,
    std::shared_ptr<NativeMethodCallInvokerCompatible> nativeInvoker
  );

  /**
   * Returns the underlying runtime object.
   */
  jsi::Runtime &get() const;

  /**
   * Evaluates given JavaScript source code.
   * @throws if the input format is unknown, or evaluation causes an error,
   * a jni::JniException<JavaScriptEvaluateException> will be thrown.
   */
  jni::local_ref<jni::HybridClass<JavaScriptValue, Destructible>::javaobject> evaluateScript(
    const std::string &script
  );

  /**
   * Returns the runtime global object for use in Kotlin.
   */
  jni::local_ref<jni::HybridClass<JavaScriptObject, Destructible>::javaobject> global();

  /**
   * Creates a new object for use in Kotlin.
   */
  jni::local_ref<jni::HybridClass<JavaScriptObject, Destructible>::javaobject> createObject();

  /**
   * Drains the JavaScript VM internal Microtask (a.k.a. event loop) queue.
   */
  void drainJSEventLoop();

  std::shared_ptr<react::CallInvoker> jsInvoker;
  std::shared_ptr<NativeMethodCallInvokerCompatible> nativeInvoker;

  std::shared_ptr<jsi::Object> getMainObject();

  JSIInteropModuleRegistry *getModuleRegistry();
private:
  std::shared_ptr<jsi::Runtime> runtime;
  std::shared_ptr<jsi::Object> mainObject;
  JSIInteropModuleRegistry *jsiInteropModuleRegistry;

  void installMainObject();
};
} // namespace expo
