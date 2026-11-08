/**
 * @license Angular v22.2.3
 * (c) 2010-2026 Google LLC. https://angular.dev/
 * License: MIT
 */

import { assertString, EMPTY_OBJ, assertFirstCreatePass, assertDefined, assertNotEqual, FLAGS, assertEqual, isInCheckNoChangesMode, PREORDER_HOOK_FLAGS, throwError, assertNumber, assertGreaterThan, HEADER_OFFSET, DECLARATION_VIEW, NG_FACTORY_DEF, isForwardRef, resolveForwardRef, getFactoryDef, convertToBitFlags, isRootView, assertTNodeForLView, enterDI, runInInjectorProfilerContext, getCurrentTNode, getLView, emitInjectorToCreateInstanceEvent, emitInstanceCreatedByInjectorEvent, throwProviderNotFoundError, leaveDI, assertNodeInjector, setInjectImplementation, injectRootLimpMode, stringifyForError, cyclicDependencyErrorWithDetails, cyclicDependencyError, setInjectorProfilerContext, assertDirectiveDef, EMBEDDED_VIEW_INJECTOR, T_HOST, assertIndexInRange, INJECTOR, TVIEW as TVIEW$1, NG_ELEMENT_ID, isComponentDef, isComponentHost, DECLARATION_COMPONENT_VIEW, makeEnvironmentProviders, InjectionToken, _global, ɵɵinvalidFactoryDep as __invalidFactoryDep, ɵɵinject as __inject, ɵɵdefineInjector as __defineInjector, ɵɵdefineInjectable as __defineInjectable, newArray, attachInjectFlag, RuntimeError, NG_PROV_DEF, getClosureSafeProperty, getNativeByTNode, registerSpecialProvider, flatten, arrayEquals, ID, isLView, assertDomNode, EMPTY_ARRAY, getComponentLViewByIndex, CONTEXT, unwrapRNode, assertLView, HOST, getLViewParent, isLContainer, CONTAINER_HEADER_OFFSET, CHILD_HEAD, NEXT, Injector, CLEANUP, getComponentDef, getDirectiveDef, APP_ID, inject, makeStateKey, formatRuntimeError, TransferState, isInSkipHydrationBlock as isInSkipHydrationBlock$1, HYDRATION, isContentQueryHost, setCurrentQueryIndex, XSS_SECURITY_URL, isDirectiveHost, MATH_ML_NAMESPACE, SVG_NAMESPACE, RENDERER, SecurityContext, renderStringify, getSelectedTNode, checkSecurityContext, getSelectedIndex, ENVIRONMENT, stringify, ANIMATIONS, AFTER_RENDER_SEQUENCES_TO_ADD, markAncestorsForTraversal, NgZone, ChangeDetectionScheduler, ErrorHandler, assertNotInReactiveContext, assertInInjectionContext, DestroyRef, ViewContext, EnvironmentInjector, isDestroyed, assertLContainer, MOVED_VIEWS, assertProjectionSlots, PARENT, NATIVE, REACTIVE_TEMPLATE_CONSUMER, DECLARATION_LCONTAINER, QUERIES, assertParentView, assertNotReactive, ON_DESTROY_HOOKS, assertFunction, EFFECTS, resetPreOrderHookFlags, CHILD_TAIL, assertSame, assertFirstUpdatePass, getTView, assertIndexInDeclRange, setSelectedIndex, INTERNAL_APPLICATION_ERROR_HANDLER, assertNotSame, isCurrentTNodeParent, setCurrentTNodeAsNotParent, assertHasParent, setCurrentTNode, getElementDepthCount, increaseElementDepthCount, wasLastNodeCreated, setCurrentDirectiveIndex, getCurrentDirectiveIndex, unwrapLView, enterView, leaveView, isCreationMode, markViewForRefresh, setIsInCheckNoChangesMode, setIsRefreshingViews, isExhaustiveCheckNoChanges, requiresRefreshOrTraversal, setBindingIndex, EFFECTS_TO_SCHEDULE, encapsulateBoundaryError, setBindingRootForHostBindings, ON_ERROR, viewAttachedToChangeDetector, CheckNoChangesMode, isRefreshingViews, removeFromArray, addToArray, updateAncestorTraversalFlagsOnAttach, storeLViewOnDestroy, VIEW_REFS, DOC_PAGE_BASE_URL, assertGreaterThanOrEqual, isInI18nBlock, assertTNodeForTView, getCurrentParentTNode, getNamespace, getCurrentTNodePlaceholderOk, assertTIcu, assertTNode, assertNumberInRange, DEHYDRATED_VIEWS, getNgModuleDef, getPipeDef as getPipeDef$1, getNgModuleDefOrThrow, isStandalone, getTNode, assertLessThan, getOrCreateTViewCleanup, getOrCreateLViewCleanup, debugStringifyTypeForError, assertNotDefined, nextBindingIndex, concatStringsWithSpace, assertInjectImplementationNotEqual, emitInjectEvent, getConstant, getDirectiveDefOrThrow, DOCUMENT as DOCUMENT$1, viewAttachedToContainer, storeCleanupWithContext, signal, createInjectorWithoutInjectorInstances, R3Injector, getNullInjector, internalImportProvidersFrom, initNgDevMode, runInInjectionContext, fillProperties, NG_COMP_DEF, NG_DIR_DEF, getBindingsEnabled, lastNodeWasCreated, arrayInsert2, arraySplice, removeLViewOnDestroy, walkUpViews, getNativeByIndex, assertElement, setInjectorProfiler, EffectRefImpl, NullInjector, getAllSpecialProviders, ENVIRONMENT_INITIALIZER, INJECTOR_DEF_TYPES, walkProviderTree, deepForEach, getInjectorDef, isTypeProvider, VERSION, retrieveTransferredState, isSignal, isInInjectionContext, PendingTasksInternal, ZONELESS_ENABLED, EffectScheduler, PendingTasks, promiseWithResolvers, decreaseElementDepthCount, assertTNodeCreationIndex, enterSkipHydrationBlock, isSkipHydrationRootTNode, leaveSkipHydrationBlock, createViewEffect, getCurrentDirectiveDef, getBindingIndex, assertIndexInExpandoRange, assertOneOf, setInI18nBlock, nextContextImpl, getCurrentQueryIndex, getContextLView, load, keyValueArrayIndexOf, incrementBindingIndex, keyValueArrayGet, keyValueArraySet, isWritableSignal, store, getBindingRoot, providerToFactory, emitProviderConfiguredEvent, isClassProvider, forwardRef, ɵɵrestoreView as __restoreView, ɵɵdisableBindings as __disableBindings, ɵɵenableBindings as __enableBindings, ɵɵnamespaceSVG as __namespaceSVG, ɵɵnamespaceMathML as __namespaceMathML, ɵɵnamespaceHTML as __namespaceHTML, ɵɵresetView as __resetView, NG_MOD_DEF, NG_INJ_DEF, NG_PIPE_DEF, PROVIDED_ZONELESS, NoopNgZone, angularZoneInstanceIdProperty, scheduleCallbackWithMicrotask, scheduleCallbackWithRafRace, SCHEDULE_IN_ROOT_ZONE, getNativeByTNodeOrNull } from './_pending_tasks-chunk.mjs';
import { setActiveConsumer as setActiveConsumer$1 } from '@angular/core/primitives/signals';
import { SIGNAL_NODE, signalSetFn, setActiveConsumer, consumerDestroy, SIGNAL, REACTIVE_NODE, consumerPollProducersForChange, consumerBeforeComputation, getActiveConsumer, consumerAfterComputation, createComputed, producerUpdateValueVersion, producerAccessed, ERRORED, setThrowInvalidWriteToSignalError } from './_effect-chunk.mjs';
import { Subject, Subscription } from 'rxjs';
import { map } from 'rxjs/operators';
import { Attribute as Attribute$1 } from './_attribute-chunk.mjs';

const REQUIRED_UNSET_VALUE = /* @__PURE__ */Symbol('InputSignalNode#UNSET');
const INPUT_SIGNAL_NODE = /* @__PURE__ */(() => {
  return {
    ...SIGNAL_NODE,
    transformFn: undefined,
    applyValueToInputSignal(node, value) {
      signalSetFn(node, value);
    }
  };
})();

function noSideEffects(fn) {
  return {
    toString: fn
  }.toString();
}

var ProfilerEvent;
(function (ProfilerEvent) {
  ProfilerEvent[ProfilerEvent["TemplateCreateStart"] = 0] = "TemplateCreateStart";
  ProfilerEvent[ProfilerEvent["TemplateCreateEnd"] = 1] = "TemplateCreateEnd";
  ProfilerEvent[ProfilerEvent["TemplateUpdateStart"] = 2] = "TemplateUpdateStart";
  ProfilerEvent[ProfilerEvent["TemplateUpdateEnd"] = 3] = "TemplateUpdateEnd";
  ProfilerEvent[ProfilerEvent["LifecycleHookStart"] = 4] = "LifecycleHookStart";
  ProfilerEvent[ProfilerEvent["LifecycleHookEnd"] = 5] = "LifecycleHookEnd";
  ProfilerEvent[ProfilerEvent["OutputStart"] = 6] = "OutputStart";
  ProfilerEvent[ProfilerEvent["OutputEnd"] = 7] = "OutputEnd";
  ProfilerEvent[ProfilerEvent["BootstrapApplicationStart"] = 8] = "BootstrapApplicationStart";
  ProfilerEvent[ProfilerEvent["BootstrapApplicationEnd"] = 9] = "BootstrapApplicationEnd";
  ProfilerEvent[ProfilerEvent["BootstrapComponentStart"] = 10] = "BootstrapComponentStart";
  ProfilerEvent[ProfilerEvent["BootstrapComponentEnd"] = 11] = "BootstrapComponentEnd";
  ProfilerEvent[ProfilerEvent["ChangeDetectionStart"] = 12] = "ChangeDetectionStart";
  ProfilerEvent[ProfilerEvent["ChangeDetectionEnd"] = 13] = "ChangeDetectionEnd";
  ProfilerEvent[ProfilerEvent["ChangeDetectionSyncStart"] = 14] = "ChangeDetectionSyncStart";
  ProfilerEvent[ProfilerEvent["ChangeDetectionSyncEnd"] = 15] = "ChangeDetectionSyncEnd";
  ProfilerEvent[ProfilerEvent["AfterRenderHooksStart"] = 16] = "AfterRenderHooksStart";
  ProfilerEvent[ProfilerEvent["AfterRenderHooksEnd"] = 17] = "AfterRenderHooksEnd";
  ProfilerEvent[ProfilerEvent["ComponentStart"] = 18] = "ComponentStart";
  ProfilerEvent[ProfilerEvent["ComponentEnd"] = 19] = "ComponentEnd";
  ProfilerEvent[ProfilerEvent["DeferBlockStateStart"] = 20] = "DeferBlockStateStart";
  ProfilerEvent[ProfilerEvent["DeferBlockStateEnd"] = 21] = "DeferBlockStateEnd";
  ProfilerEvent[ProfilerEvent["DynamicComponentStart"] = 22] = "DynamicComponentStart";
  ProfilerEvent[ProfilerEvent["DynamicComponentEnd"] = 23] = "DynamicComponentEnd";
  ProfilerEvent[ProfilerEvent["HostBindingsUpdateStart"] = 24] = "HostBindingsUpdateStart";
  ProfilerEvent[ProfilerEvent["HostBindingsUpdateEnd"] = 25] = "HostBindingsUpdateEnd";
})(ProfilerEvent || (ProfilerEvent = {}));

class SimpleChange {
  previousValue;
  currentValue;
  firstChange;
  constructor(previousValue, currentValue, firstChange) {
    this.previousValue = previousValue;
    this.currentValue = currentValue;
    this.firstChange = firstChange;
  }
  isFirstChange() {
    return this.firstChange;
  }
}

function applyValueToInputField(instance, inputSignalNode, privateName, value) {
  if (inputSignalNode !== null) {
    inputSignalNode.applyValueToInputSignal(inputSignalNode, value);
  } else {
    instance[privateName] = value;
  }
}

let _ngOnChangesFeatureImpl = null;
const ɵɵNgOnChangesFeature = /* @__PURE__ */(() => {
  _ngOnChangesFeatureImpl = NgOnChangesFeatureImpl;
  const ɵɵNgOnChangesFeatureImpl = () => NgOnChangesFeatureImpl;
  ɵɵNgOnChangesFeatureImpl.ngInherit = true;
  return ɵɵNgOnChangesFeatureImpl;
})();
function getNgOnChangesFeatureImpl() {
  return _ngOnChangesFeatureImpl;
}
function NgOnChangesFeatureImpl(definition) {
  if (definition.type.prototype.ngOnChanges) {
    definition.setInput = ngOnChangesSetInput;
  }
  return rememberChangeHistoryAndInvokeOnChangesHook;
}
function rememberChangeHistoryAndInvokeOnChangesHook() {
  const simpleChangesStore = getSimpleChangesStore(this);
  const current = simpleChangesStore?.current;
  if (current) {
    const previous = simpleChangesStore.previous;
    if (previous === EMPTY_OBJ) {
      simpleChangesStore.previous = current;
    } else {
      for (let key in current) {
        previous[key] = current[key];
      }
    }
    simpleChangesStore.current = null;
    this.ngOnChanges(current);
  }
}
function ngOnChangesSetInput(instance, inputSignalNode, value, publicName, privateName) {
  const declaredName = this.declaredInputs[publicName];
  ngDevMode && assertString(declaredName, 'Name of input in ngOnChanges has to be a string');
  const simpleChangesStore = getSimpleChangesStore(instance) || setSimpleChangesStore(instance, {
    previous: EMPTY_OBJ,
    current: null
  });
  const current = simpleChangesStore.current || (simpleChangesStore.current = {});
  const previous = simpleChangesStore.previous;
  const previousChange = previous[declaredName];
  current[declaredName] = new SimpleChange(previousChange && previousChange.currentValue, value, previous === EMPTY_OBJ);
  applyValueToInputField(instance, inputSignalNode, privateName, value);
}
const SIMPLE_CHANGES_STORE = '__ngSimpleChanges__';
function getSimpleChangesStore(instance) {
  return Object.hasOwn(instance, SIMPLE_CHANGES_STORE) ? instance[SIMPLE_CHANGES_STORE] || null : null;
}
function setSimpleChangesStore(instance, store) {
  return instance[SIMPLE_CHANGES_STORE] = store;
}

const profilerCallbacks = [];
const NOOP_PROFILER_REMOVAL = () => {};
function removeProfiler(profiler) {
  const profilerIdx = profilerCallbacks.indexOf(profiler);
  if (profilerIdx !== -1) {
    profilerCallbacks.splice(profilerIdx, 1);
  }
}
function setProfiler(profiler) {
  if (profiler !== null) {
    if (!profilerCallbacks.includes(profiler)) {
      profilerCallbacks.push(profiler);
    }
    return () => removeProfiler(profiler);
  } else {
    profilerCallbacks.length = 0;
    return NOOP_PROFILER_REMOVAL;
  }
}
const profiler = function (event, instance = null, eventFn) {
  for (let i = 0; i < profilerCallbacks.length; i++) {
    const profilerCallback = profilerCallbacks[i];
    profilerCallback(event, instance, eventFn);
  }
};

function registerPreOrderHooks(directiveIndex, directiveDef, tView) {
  ngDevMode && assertFirstCreatePass(tView);
  const {
    ngOnChanges,
    ngOnInit,
    ngDoCheck
  } = directiveDef.type.prototype;
  if (ngOnChanges) {
    const wrappedOnChanges = getNgOnChangesFeatureImpl()(directiveDef);
    (tView.preOrderHooks ??= []).push(directiveIndex, wrappedOnChanges);
    (tView.preOrderCheckHooks ??= []).push(directiveIndex, wrappedOnChanges);
  }
  if (ngOnInit) {
    (tView.preOrderHooks ??= []).push(0 - directiveIndex, ngOnInit);
  }
  if (ngDoCheck) {
    (tView.preOrderHooks ??= []).push(directiveIndex, ngDoCheck);
    (tView.preOrderCheckHooks ??= []).push(directiveIndex, ngDoCheck);
  }
}
function registerPostOrderHooks(tView, tNode) {
  ngDevMode && assertFirstCreatePass(tView);
  for (let i = tNode.directiveStart, end = tNode.directiveEnd; i < end; i++) {
    const directiveDef = tView.data[i];
    ngDevMode && assertDefined(directiveDef, 'Expecting DirectiveDef');
    const lifecycleHooks = directiveDef.type.prototype;
    const {
      ngAfterContentInit,
      ngAfterContentChecked,
      ngAfterViewInit,
      ngAfterViewChecked,
      ngOnDestroy
    } = lifecycleHooks;
    if (ngAfterContentInit) {
      (tView.contentHooks ??= []).push(-i, ngAfterContentInit);
    }
    if (ngAfterContentChecked) {
      (tView.contentHooks ??= []).push(i, ngAfterContentChecked);
      (tView.contentCheckHooks ??= []).push(i, ngAfterContentChecked);
    }
    if (ngAfterViewInit) {
      (tView.viewHooks ??= []).push(-i, ngAfterViewInit);
    }
    if (ngAfterViewChecked) {
      (tView.viewHooks ??= []).push(i, ngAfterViewChecked);
      (tView.viewCheckHooks ??= []).push(i, ngAfterViewChecked);
    }
    if (ngOnDestroy != null) {
      (tView.destroyHooks ??= []).push(i, ngOnDestroy);
    }
  }
}
function executeCheckHooks(lView, hooks, nodeIndex) {
  callHooks(lView, hooks, 3, nodeIndex);
}
function executeInitAndCheckHooks(lView, hooks, initPhase, nodeIndex) {
  ngDevMode && assertNotEqual(initPhase, 3, 'Init pre-order hooks should not be called more than once');
  if ((lView[FLAGS] & 3) === initPhase) {
    callHooks(lView, hooks, initPhase, nodeIndex);
  }
}
function incrementInitPhaseFlags(lView, initPhase) {
  ngDevMode && assertNotEqual(initPhase, 3, 'Init hooks phase should not be incremented after all init hooks have been run.');
  let flags = lView[FLAGS];
  if ((flags & 3) === initPhase) {
    flags &= 16383;
    flags += 1;
    lView[FLAGS] = flags;
  }
}
function callHooks(currentView, arr, initPhase, currentNodeIndex) {
  ngDevMode && assertEqual(isInCheckNoChangesMode(), false, 'Hooks should never be run when in check no changes mode.');
  const startIndex = currentNodeIndex !== undefined ? currentView[PREORDER_HOOK_FLAGS] & 65535 : 0;
  const nodeIndexLimit = currentNodeIndex != null ? currentNodeIndex : -1;
  const max = arr.length - 1;
  let lastNodeIndexFound = 0;
  for (let i = startIndex; i < max; i++) {
    const hook = arr[i + 1];
    if (typeof hook === 'number') {
      lastNodeIndexFound = arr[i];
      if (currentNodeIndex != null && lastNodeIndexFound >= currentNodeIndex) {
        break;
      }
    } else {
      const isInitHook = arr[i] < 0;
      if (isInitHook) {
        currentView[PREORDER_HOOK_FLAGS] += 65536;
      }
      if (lastNodeIndexFound < nodeIndexLimit || nodeIndexLimit == -1) {
        callHook(currentView, initPhase, arr, i);
        currentView[PREORDER_HOOK_FLAGS] = (currentView[PREORDER_HOOK_FLAGS] & 4294901760) + i + 2;
      }
      i++;
    }
  }
}
function callHookInternal(directive, hook) {
  profiler(ProfilerEvent.LifecycleHookStart, directive, hook);
  const prevConsumer = setActiveConsumer(null);
  try {
    hook.call(directive);
  } finally {
    setActiveConsumer(prevConsumer);
    profiler(ProfilerEvent.LifecycleHookEnd, directive, hook);
  }
}
function callHook(currentView, initPhase, arr, i) {
  const isInitHook = arr[i] < 0;
  const hook = arr[i + 1];
  const directiveIndex = isInitHook ? -arr[i] : arr[i];
  const directive = currentView[directiveIndex];
  if (isInitHook) {
    const indexWithintInitPhase = currentView[FLAGS] >> 14;
    if (indexWithintInitPhase < currentView[PREORDER_HOOK_FLAGS] >> 16 && (currentView[FLAGS] & 3) === initPhase) {
      currentView[FLAGS] += 16384;
      callHookInternal(directive, hook);
    }
  } else {
    callHookInternal(directive, hook);
  }
}

const NO_PARENT_INJECTOR = -1;
class NodeInjectorFactory {
  factory;
  name;
  injectImpl;
  resolving = false;
  canSeeViewProviders;
  multi;
  componentProviders;
  index;
  providerFactory;
  constructor(factory, isViewProvider, injectImplementation, name) {
    this.factory = factory;
    this.name = name;
    ngDevMode && assertDefined(factory, 'Factory not specified');
    ngDevMode && assertEqual(typeof factory, 'function', 'Expected factory function.');
    this.canSeeViewProviders = isViewProvider;
    this.injectImpl = injectImplementation;
  }
}

function toTNodeTypeAsString(tNodeType) {
  let text = '';
  tNodeType & 1 && (text += '|Text');
  tNodeType & 2 && (text += '|Element');
  tNodeType & 4 && (text += '|Container');
  tNodeType & 8 && (text += '|ElementContainer');
  tNodeType & 16 && (text += '|Projection');
  tNodeType & 32 && (text += '|IcuContainer');
  tNodeType & 64 && (text += '|Placeholder');
  tNodeType & 128 && (text += '|LetDeclaration');
  return text.length > 0 ? text.substring(1) : text;
}
function isTNodeShape(value) {
  return value != null && typeof value === 'object' && (value.insertBeforeIndex === null || typeof value.insertBeforeIndex === 'number' || Array.isArray(value.insertBeforeIndex));
}
function isLetDeclaration(tNode) {
  return !!(tNode.type & 128);
}
function hasClassInput(tNode) {
  return (tNode.flags & 8) !== 0;
}
function hasStyleInput(tNode) {
  return (tNode.flags & 16) !== 0;
}

function assertTNodeType(tNode, expectedTypes, message) {
  assertDefined(tNode, 'should be called with a TNode');
  if ((tNode.type & expectedTypes) === 0) {
    throwError(message || `Expected [${toTNodeTypeAsString(expectedTypes)}] but got ${toTNodeTypeAsString(tNode.type)}.`);
  }
}
function assertPureTNodeType(type) {
  if (!(type === 2 || type === 1 || type === 4 || type === 8 || type === 32 || type === 16 || type === 64 || type === 128)) {
    throwError(`Expected TNodeType to have only a single type selected, but got ${toTNodeTypeAsString(type)}.`);
  }
}

function setUpAttributes(renderer, native, attrs) {
  let i = 0;
  while (i < attrs.length) {
    const value = attrs[i];
    if (typeof value === 'number') {
      if (value !== 0) {
        break;
      }
      i++;
      const namespaceURI = attrs[i++];
      const attrName = attrs[i++];
      const attrVal = attrs[i++];
      renderer.setAttribute(native, attrName, attrVal, namespaceURI);
    } else {
      const attrName = value;
      const attrVal = attrs[++i];
      if (isAnimationProp(attrName)) {
        renderer.setProperty(native, attrName, attrVal);
      } else {
        renderer.setAttribute(native, attrName, attrVal);
      }
      i++;
    }
  }
  return i;
}
function isNameOnlyAttributeMarker(marker) {
  return marker === 3 || marker === 4 || marker === 6;
}
function isAnimationProp(name) {
  return name.charCodeAt(0) === 64;
}
function mergeHostAttrs(dst, src) {
  if (src === null || src.length === 0) ; else if (dst === null || dst.length === 0) {
    dst = src.slice();
  } else {
    let srcMarker = -1;
    for (let i = 0; i < src.length; i++) {
      const item = src[i];
      if (typeof item === 'number') {
        srcMarker = item;
      } else {
        if (srcMarker === 0) ; else if (srcMarker === -1 || srcMarker === 2) {
          mergeHostAttribute(dst, srcMarker, item, null, src[++i]);
        } else {
          mergeHostAttribute(dst, srcMarker, item, null, null);
        }
      }
    }
  }
  return dst;
}
function mergeHostAttribute(dst, marker, key1, key2, value) {
  let i = 0;
  let markerInsertPosition = dst.length;
  if (marker === -1) {
    markerInsertPosition = -1;
  } else {
    while (i < dst.length) {
      const dstValue = dst[i++];
      if (typeof dstValue === 'number') {
        if (dstValue === marker) {
          markerInsertPosition = -1;
          break;
        } else if (dstValue > marker) {
          markerInsertPosition = i - 1;
          break;
        }
      }
    }
  }
  while (i < dst.length) {
    const item = dst[i];
    if (typeof item === 'number') {
      break;
    } else if (item === key1) {
      {
        if (value !== null) {
          dst[i + 1] = value;
        }
        return;
      }
    }
    i++;
    if (value !== null) i++;
  }
  if (markerInsertPosition !== -1) {
    dst.splice(markerInsertPosition, 0, marker);
    i = markerInsertPosition + 1;
  }
  dst.splice(i++, 0, key1);
  if (value !== null) {
    dst.splice(i++, 0, value);
  }
}

function hasParentInjector(parentLocation) {
  return parentLocation !== NO_PARENT_INJECTOR;
}
function getParentInjectorIndex(parentLocation) {
  if (ngDevMode) {
    assertNumber(parentLocation, 'Number expected');
    assertNotEqual(parentLocation, -1, 'Not a valid state.');
    const parentInjectorIndex = parentLocation & 32767;
    assertGreaterThan(parentInjectorIndex, HEADER_OFFSET, 'Parent injector must be pointing past HEADER_OFFSET.');
  }
  return parentLocation & 32767;
}
function getParentInjectorViewOffset(parentLocation) {
  return parentLocation >> 16;
}
function getParentInjectorView(location, startView) {
  let viewOffset = getParentInjectorViewOffset(location);
  let parentView = startView;
  while (viewOffset > 0) {
    parentView = parentView[DECLARATION_VIEW];
    viewOffset--;
  }
  return parentView;
}

let includeViewProviders = true;
function setIncludeViewProviders(v) {
  const oldValue = includeViewProviders;
  includeViewProviders = v;
  return oldValue;
}
const BLOOM_SIZE = 256;
const BLOOM_MASK = BLOOM_SIZE - 1;
const BLOOM_BUCKET_BITS = 5;
let nextNgElementId = 0;
const NOT_FOUND = {};
function bloomAdd(injectorIndex, tView, type) {
  ngDevMode && assertEqual(tView.firstCreatePass, true, 'expected firstCreatePass to be true');
  let id;
  if (typeof type === 'string') {
    id = type.charCodeAt(0) || 0;
  } else if (Object.hasOwn(type, NG_ELEMENT_ID)) {
    id = type[NG_ELEMENT_ID];
  }
  if (id == null) {
    id = type[NG_ELEMENT_ID] = nextNgElementId++;
  }
  const bloomHash = id & BLOOM_MASK;
  const mask = 1 << bloomHash;
  tView.data[injectorIndex + (bloomHash >> BLOOM_BUCKET_BITS)] |= mask;
}
function getOrCreateNodeInjectorForNode(tNode, lView) {
  const existingInjectorIndex = getInjectorIndex(tNode, lView);
  if (existingInjectorIndex !== -1) {
    return existingInjectorIndex;
  }
  const tView = lView[TVIEW$1];
  if (tView.firstCreatePass) {
    tNode.injectorIndex = lView.length;
    insertBloom(tView.data, tNode);
    insertBloom(lView, null);
    insertBloom(tView.blueprint, null);
  }
  const parentLoc = getParentInjectorLocation(tNode, lView);
  const injectorIndex = tNode.injectorIndex;
  if (hasParentInjector(parentLoc)) {
    const parentIndex = getParentInjectorIndex(parentLoc);
    const parentLView = getParentInjectorView(parentLoc, lView);
    const parentData = parentLView[TVIEW$1].data;
    for (let i = 0; i < 8; i++) {
      lView[injectorIndex + i] = parentLView[parentIndex + i] | parentData[parentIndex + i];
    }
  }
  lView[injectorIndex + 8] = parentLoc;
  return injectorIndex;
}
function insertBloom(arr, footer) {
  arr.push(0, 0, 0, 0, 0, 0, 0, 0, footer);
}
function getInjectorIndex(tNode, lView) {
  if (tNode.injectorIndex === -1 || tNode.parent && tNode.parent.injectorIndex === tNode.injectorIndex || lView[tNode.injectorIndex + 8] === null) {
    return -1;
  } else {
    ngDevMode && assertIndexInRange(lView, tNode.injectorIndex);
    return tNode.injectorIndex;
  }
}
function getParentInjectorLocation(tNode, lView) {
  if (tNode.parent && tNode.parent.injectorIndex !== -1) {
    return tNode.parent.injectorIndex;
  }
  let declarationViewOffset = 0;
  let parentTNode = null;
  let lViewCursor = lView;
  while (lViewCursor !== null) {
    parentTNode = getTNodeFromLView(lViewCursor);
    if (parentTNode === null) {
      return NO_PARENT_INJECTOR;
    }
    ngDevMode && parentTNode && assertTNodeForLView(parentTNode, lViewCursor[DECLARATION_VIEW]);
    declarationViewOffset++;
    lViewCursor = lViewCursor[DECLARATION_VIEW];
    if (parentTNode.injectorIndex !== -1) {
      return parentTNode.injectorIndex | declarationViewOffset << 16;
    }
  }
  return NO_PARENT_INJECTOR;
}
function diPublicInInjector(injectorIndex, tView, token) {
  bloomAdd(injectorIndex, tView, token);
}
function injectAttributeImpl(tNode, attrNameToInject) {
  ngDevMode && assertTNodeType(tNode, 12 | 3);
  ngDevMode && assertDefined(tNode, 'expecting tNode');
  if (attrNameToInject === 'class') {
    return tNode.classes;
  }
  if (attrNameToInject === 'style') {
    return tNode.styles;
  }
  const attrs = tNode.attrs;
  if (attrs) {
    const attrsLength = attrs.length;
    let i = 0;
    while (i < attrsLength) {
      const value = attrs[i];
      if (isNameOnlyAttributeMarker(value)) break;
      if (value === 0) {
        i = i + 2;
      } else if (typeof value === 'number') {
        i++;
        while (i < attrsLength && typeof attrs[i] === 'string') {
          i++;
        }
      } else if (value === attrNameToInject) {
        return attrs[i + 1];
      } else {
        i = i + 2;
      }
    }
  }
  return null;
}
function notFoundValueOrThrow(notFoundValue, token, flags) {
  if (flags & 8 || notFoundValue !== undefined) {
    return notFoundValue;
  } else {
    throwProviderNotFoundError(token, 'NodeInjector');
  }
}
function lookupTokenUsingModuleInjector(lView, token, flags, notFoundValue) {
  if (flags & 8 && notFoundValue === undefined) {
    notFoundValue = null;
  }
  if ((flags & (2 | 1)) === 0) {
    const moduleInjector = lView[INJECTOR];
    const previousInjectImplementation = setInjectImplementation(undefined);
    try {
      if (moduleInjector) {
        return moduleInjector.get(token, notFoundValue, flags & 8);
      } else {
        return injectRootLimpMode(token, notFoundValue, flags & 8);
      }
    } finally {
      setInjectImplementation(previousInjectImplementation);
    }
  }
  return notFoundValueOrThrow(notFoundValue, token, flags);
}
function getOrCreateInjectable(tNode, lView, token, flags = 0, notFoundValue) {
  if (tNode !== null) {
    if (lView[FLAGS] & 2048 && !(flags & 2)) {
      const embeddedInjectorValue = lookupTokenUsingEmbeddedInjector(tNode, lView, token, flags, NOT_FOUND);
      if (embeddedInjectorValue !== NOT_FOUND) {
        return embeddedInjectorValue;
      }
    }
    const value = lookupTokenUsingNodeInjector(tNode, lView, token, flags, NOT_FOUND);
    if (value !== NOT_FOUND) {
      return value;
    }
  }
  return lookupTokenUsingModuleInjector(lView, token, flags, notFoundValue);
}
function lookupTokenUsingNodeInjector(tNode, lView, token, flags, notFoundValue) {
  const bloomHash = bloomHashBitOrFactory(token);
  if (typeof bloomHash === 'function') {
    if (!enterDI(lView, tNode, flags)) {
      return flags & 1 ? notFoundValueOrThrow(notFoundValue, token, flags) : lookupTokenUsingModuleInjector(lView, token, flags, notFoundValue);
    }
    try {
      let value;
      if (ngDevMode) {
        runInInjectorProfilerContext(new NodeInjector(getCurrentTNode(), getLView()), token, () => {
          emitInjectorToCreateInstanceEvent(token);
          value = bloomHash(flags);
          emitInstanceCreatedByInjectorEvent(value);
        });
      } else {
        value = bloomHash(flags);
      }
      if (value == null && !(flags & 8)) {
        throwProviderNotFoundError(token);
      } else {
        return value;
      }
    } finally {
      leaveDI();
    }
  } else if (typeof bloomHash === 'number') {
    let previousTView = null;
    let injectorIndex = getInjectorIndex(tNode, lView);
    let parentLocation = NO_PARENT_INJECTOR;
    let hostTElementNode = flags & 1 ? lView[DECLARATION_COMPONENT_VIEW][T_HOST] : null;
    if (injectorIndex === -1 || flags & 4) {
      parentLocation = injectorIndex === -1 ? getParentInjectorLocation(tNode, lView) : lView[injectorIndex + 8];
      if (parentLocation === NO_PARENT_INJECTOR || !shouldSearchParent(flags, false)) {
        injectorIndex = -1;
      } else {
        previousTView = lView[TVIEW$1];
        injectorIndex = getParentInjectorIndex(parentLocation);
        lView = getParentInjectorView(parentLocation, lView);
      }
    }
    while (injectorIndex !== -1) {
      ngDevMode && assertNodeInjector(lView, injectorIndex);
      const tView = lView[TVIEW$1];
      ngDevMode && assertTNodeForLView(tView.data[injectorIndex + 8], lView);
      if (bloomHasToken(bloomHash, injectorIndex, tView.data)) {
        const instance = searchTokensOnInjector(injectorIndex, lView, token, previousTView, flags, hostTElementNode);
        if (instance !== NOT_FOUND) {
          return instance;
        }
      }
      parentLocation = lView[injectorIndex + 8];
      if (parentLocation !== NO_PARENT_INJECTOR && shouldSearchParent(flags, lView[TVIEW$1].data[injectorIndex + 8] === hostTElementNode) && bloomHasToken(bloomHash, injectorIndex, lView)) {
        previousTView = tView;
        injectorIndex = getParentInjectorIndex(parentLocation);
        lView = getParentInjectorView(parentLocation, lView);
      } else {
        injectorIndex = -1;
      }
    }
  }
  return notFoundValue;
}
function searchTokensOnInjector(injectorIndex, lView, token, previousTView, flags, hostTElementNode) {
  const currentTView = lView[TVIEW$1];
  const tNode = currentTView.data[injectorIndex + 8];
  const canAccessViewProviders = previousTView == null ? isComponentHost(tNode) && includeViewProviders : previousTView != currentTView && (tNode.type & 3) !== 0;
  const isHostSpecialCase = flags & 1 && hostTElementNode === tNode;
  const injectableIdx = locateDirectiveOrProvider(tNode, currentTView, token, canAccessViewProviders, isHostSpecialCase);
  if (injectableIdx !== null) {
    return getNodeInjectable(lView, currentTView, injectableIdx, tNode, flags);
  } else {
    return NOT_FOUND;
  }
}
function locateDirectiveOrProvider(tNode, tView, token, canAccessViewProviders, isHostSpecialCase) {
  const nodeProviderIndexes = tNode.providerIndexes;
  const tInjectables = tView.data;
  const injectablesStart = nodeProviderIndexes & 1048575;
  const directivesStart = tNode.directiveStart;
  const directiveEnd = tNode.directiveEnd;
  const cptViewProvidersCount = nodeProviderIndexes >> 20;
  const startingIndex = canAccessViewProviders ? injectablesStart : injectablesStart + cptViewProvidersCount;
  const endIndex = isHostSpecialCase ? injectablesStart + cptViewProvidersCount : directiveEnd;
  for (let i = startingIndex; i < endIndex; i++) {
    const providerTokenOrDef = tInjectables[i];
    if (i < directivesStart && token === providerTokenOrDef || i >= directivesStart && providerTokenOrDef.type === token) {
      return i;
    }
  }
  if (isHostSpecialCase) {
    const dirDef = tInjectables[directivesStart];
    if (dirDef && isComponentDef(dirDef) && dirDef.type === token) {
      return directivesStart;
    }
  }
  return null;
}
let injectionPath = [];
function getNodeInjectable(lView, tView, index, tNode, flags) {
  let value = lView[index];
  const tData = tView.data;
  if (value instanceof NodeInjectorFactory) {
    const factory = value;
    ngDevMode && injectionPath.push(factory.name ?? 'unknown');
    if (factory.resolving) {
      let token = '';
      if (ngDevMode) {
        token = stringifyForError(tData[index]);
        throw cyclicDependencyErrorWithDetails(token, injectionPath);
      } else {
        throw cyclicDependencyError(token);
      }
    }
    const previousIncludeViewProviders = setIncludeViewProviders(factory.canSeeViewProviders);
    factory.resolving = true;
    const token = tData[index].type || tData[index];
    let prevInjectContext;
    if (ngDevMode) {
      const injector = new NodeInjector(tNode, lView);
      prevInjectContext = setInjectorProfilerContext({
        injector,
        token
      });
    }
    const previousInjectImplementation = factory.injectImpl ? setInjectImplementation(factory.injectImpl) : null;
    const success = enterDI(lView, tNode, 0);
    ngDevMode && assertEqual(success, true, "Because flags do not contain `SkipSelf' we expect this to always succeed.");
    try {
      ngDevMode && emitInjectorToCreateInstanceEvent(token);
      value = lView[index] = factory.factory(undefined, flags, tData, lView, tNode);
      ngDevMode && emitInstanceCreatedByInjectorEvent(value);
      if (tView.firstCreatePass && index >= tNode.directiveStart) {
        ngDevMode && assertDirectiveDef(tData[index]);
        registerPreOrderHooks(index, tData[index], tView);
      }
    } finally {
      ngDevMode && setInjectorProfilerContext(prevInjectContext);
      previousInjectImplementation !== null && setInjectImplementation(previousInjectImplementation);
      setIncludeViewProviders(previousIncludeViewProviders);
      factory.resolving = false;
      leaveDI();
      ngDevMode && (injectionPath = []);
    }
  }
  return value;
}
function bloomHashBitOrFactory(token) {
  ngDevMode && assertDefined(token, 'token must be defined');
  if (typeof token === 'string') {
    return token.charCodeAt(0) || 0;
  }
  const tokenId = Object.hasOwn(token, NG_ELEMENT_ID) ? token[NG_ELEMENT_ID] : undefined;
  if (typeof tokenId === 'number') {
    if (tokenId >= 0) {
      return tokenId & BLOOM_MASK;
    } else {
      ngDevMode && assertEqual(tokenId, -1, 'Expecting to get Special Injector Id');
      return createNodeInjector;
    }
  } else {
    return tokenId;
  }
}
function bloomHasToken(bloomHash, injectorIndex, injectorView) {
  const mask = 1 << bloomHash;
  const value = injectorView[injectorIndex + (bloomHash >> BLOOM_BUCKET_BITS)];
  return !!(value & mask);
}
function shouldSearchParent(flags, isFirstHostTNode) {
  return !(flags & 2) && !(flags & 1 && isFirstHostTNode);
}
function getNodeInjectorLView(nodeInjector) {
  return nodeInjector._lView;
}
function getNodeInjectorTNode(nodeInjector) {
  return nodeInjector._tNode;
}
class NodeInjector {
  _tNode;
  _lView;
  constructor(_tNode, _lView) {
    this._tNode = _tNode;
    this._lView = _lView;
  }
  get(token, notFoundValue, flags) {
    return getOrCreateInjectable(this._tNode, this._lView, token, convertToBitFlags(flags), notFoundValue);
  }
}
function createNodeInjector() {
  return new NodeInjector(getCurrentTNode(), getLView());
}
function ɵɵgetInheritedFactory(type) {
  return noSideEffects(() => {
    const ownConstructor = type.prototype.constructor;
    const ownFactory = ownConstructor[NG_FACTORY_DEF] || getFactoryOf(ownConstructor);
    const objectPrototype = Object.prototype;
    let parent = Object.getPrototypeOf(type.prototype).constructor;
    while (parent && parent !== objectPrototype) {
      const factory = parent[NG_FACTORY_DEF] || getFactoryOf(parent);
      if (factory && factory !== ownFactory) {
        return factory;
      }
      parent = Object.getPrototypeOf(parent);
    }
    return t => new t();
  });
}
function getFactoryOf(type) {
  if (isForwardRef(type)) {
    return () => {
      const factory = getFactoryOf(resolveForwardRef(type));
      return factory && factory();
    };
  }
  return getFactoryDef(type);
}
function lookupTokenUsingEmbeddedInjector(tNode, lView, token, flags, notFoundValue) {
  let currentTNode = tNode;
  let currentLView = lView;
  while (currentTNode !== null && currentLView !== null && currentLView[FLAGS] & 2048 && !isRootView(currentLView)) {
    ngDevMode && assertTNodeForLView(currentTNode, currentLView);
    const nodeInjectorValue = lookupTokenUsingNodeInjector(currentTNode, currentLView, token, flags | 2, NOT_FOUND);
    if (nodeInjectorValue !== NOT_FOUND) {
      return nodeInjectorValue;
    }
    flags &= -5;
    let parentTNode = currentTNode.parent;
    if (!parentTNode) {
      const embeddedViewInjector = currentLView[EMBEDDED_VIEW_INJECTOR];
      if (embeddedViewInjector) {
        const embeddedViewInjectorValue = embeddedViewInjector.get(token, NOT_FOUND, flags);
        if (embeddedViewInjectorValue !== NOT_FOUND) {
          return embeddedViewInjectorValue;
        }
      }
      parentTNode = getTNodeFromLView(currentLView);
      currentLView = currentLView[DECLARATION_VIEW];
    }
    currentTNode = parentTNode;
  }
  return notFoundValue;
}
function getTNodeFromLView(lView) {
  const tView = lView[TVIEW$1];
  const tViewType = tView.type;
  if (tViewType === 2) {
    ngDevMode && assertDefined(tView.declTNode, 'Embedded TNodes should have declaration parents.');
    return tView.declTNode;
  } else if (tViewType === 1) {
    return lView[T_HOST];
  }
  return null;
}

function ɵɵinjectAttribute(attrNameToInject) {
  return injectAttributeImpl(getCurrentTNode(), attrNameToInject);
}

const _requestIdleCallback = () => (typeof requestIdleCallback !== 'undefined' ? requestIdleCallback : cb => setTimeout(cb)).bind(globalThis);
const _cancelIdleCallback = () => (typeof requestIdleCallback !== 'undefined' ? cancelIdleCallback : clearTimeout).bind(globalThis);
const IDLE_SERVICE = new InjectionToken(ngDevMode ? 'IDLE_SERVICE' : '', {
  factory: () => new RequestIdleCallbackService()
});
function provideIdleServiceWith(useExisting) {
  return makeEnvironmentProviders([{
    provide: IDLE_SERVICE,
    useExisting
  }]);
}
class RequestIdleCallbackService {
  requestIdleCallback = _requestIdleCallback();
  cancelIdleCallback = _cancelIdleCallback();
  requestOnIdle(callback, options) {
    return this.requestIdleCallback(callback, options);
  }
  cancelOnIdle(id) {
    return this.cancelIdleCallback(id);
  }
}

const ANNOTATIONS = '__annotations__';
const PARAMETERS = '__parameters__';
const PROP_METADATA = '__prop__metadata__';
function makeDecorator(name, props, parentClass, additionalProcessing, typeFn) {
  return noSideEffects(() => {
    const metaCtor = makeMetadataCtor(props);
    function DecoratorFactory(...args) {
      if (this instanceof DecoratorFactory) {
        metaCtor.call(this, ...args);
        return this;
      }
      const annotationInstance = new DecoratorFactory(...args);
      return function TypeDecorator(cls) {
        if (typeFn) typeFn(cls, ...args);
        const annotations = Object.hasOwn(cls, ANNOTATIONS) ? cls[ANNOTATIONS] : Object.defineProperty(cls, ANNOTATIONS, {
          value: []
        })[ANNOTATIONS];
        annotations.push(annotationInstance);
        return cls;
      };
    }
    if (parentClass) {
      DecoratorFactory.prototype = Object.create(parentClass.prototype);
    }
    DecoratorFactory.prototype.ngMetadataName = name;
    DecoratorFactory.annotationCls = DecoratorFactory;
    return DecoratorFactory;
  });
}
function makeMetadataCtor(props) {
  return function ctor(...args) {
    if (props) {
      const values = props(...args);
      for (const propName in values) {
        this[propName] = values[propName];
      }
    }
  };
}
function makeParamDecorator(name, props, parentClass) {
  return noSideEffects(() => {
    const metaCtor = makeMetadataCtor(props);
    function ParamDecoratorFactory(...args) {
      if (this instanceof ParamDecoratorFactory) {
        metaCtor.apply(this, args);
        return this;
      }
      const annotationInstance = new ParamDecoratorFactory(...args);
      ParamDecorator.annotation = annotationInstance;
      return ParamDecorator;
      function ParamDecorator(cls, unusedKey, index) {
        const parameters = Object.hasOwn(cls, PARAMETERS) ? cls[PARAMETERS] : Object.defineProperty(cls, PARAMETERS, {
          value: []
        })[PARAMETERS];
        while (parameters.length <= index) {
          parameters.push(null);
        }
        (parameters[index] = parameters[index] || []).push(annotationInstance);
        return cls;
      }
    }
    ParamDecoratorFactory.prototype.ngMetadataName = name;
    ParamDecoratorFactory.annotationCls = ParamDecoratorFactory;
    return ParamDecoratorFactory;
  });
}
function makePropDecorator(name, props, parentClass, additionalProcessing) {
  return noSideEffects(() => {
    const metaCtor = makeMetadataCtor(props);
    function PropDecoratorFactory(...args) {
      if (this instanceof PropDecoratorFactory) {
        metaCtor.apply(this, args);
        return this;
      }
      const decoratorInstance = new PropDecoratorFactory(...args);
      function PropDecorator(target, name) {
        if (target === undefined) {
          throw new Error('Standard Angular field decorators are not supported in JIT mode.');
        }
        const constructor = target.constructor;
        const meta = Object.hasOwn(constructor, PROP_METADATA) ? constructor[PROP_METADATA] : Object.defineProperty(constructor, PROP_METADATA, {
          value: {}
        })[PROP_METADATA];
        meta[name] = Object.hasOwn(meta, name) && meta[name] || [];
        meta[name].unshift(decoratorInstance);
      }
      return PropDecorator;
    }
    if (parentClass) {
      PropDecoratorFactory.prototype = Object.create(parentClass.prototype);
    }
    PropDecoratorFactory.prototype.ngMetadataName = name;
    PropDecoratorFactory.annotationCls = PropDecoratorFactory;
    return PropDecoratorFactory;
  });
}

function getCompilerFacade(request) {
  const globalNg = _global['ng'];
  if (globalNg && globalNg.ɵcompilerFacade) {
    return globalNg.ɵcompilerFacade;
  }
  if (typeof ngDevMode === 'undefined' || ngDevMode) {
    console.error(`JIT compilation failed for ${request.kind}`, request.type);
    let message = `The ${request.kind} '${request.type.name}' needs to be compiled using the JIT compiler, but '@angular/compiler' is not available.\n\n`;
    if (request.usage === 1) {
      message += `The ${request.kind} is part of a library that has been partially compiled.\n`;
      message += `However, the Angular Linker has not processed the library such that JIT compilation is used as fallback.\n`;
      message += '\n';
      message += `Ideally, the library is processed using the Angular Linker to become fully AOT compiled.\n`;
    } else {
      message += `JIT compilation is discouraged for production use-cases! Consider using AOT mode instead.\n`;
    }
    message += `Alternatively, the JIT compiler should be loaded by bootstrapping using '@angular/platform-browser-dynamic' or '@angular/platform-server',\n`;
    message += `or manually provide the compiler with 'import "@angular/compiler";' before bootstrapping.`;
    throw new Error(message);
  } else {
    throw new Error('JIT compiler unavailable');
  }
}

function ɵɵdefineService(opts) {
  return {
    token: opts.token,
    providedIn: opts.autoProvided === false ? null : 'root',
    factory: opts.factory,
    value: undefined
  };
}

const angularCoreDiEnv = {
  'ɵɵdefineInjectable': __defineInjectable,
  'ɵɵdefineInjector': __defineInjector,
  'ɵɵdefineService': ɵɵdefineService,
  'ɵɵinject': __inject,
  'ɵɵinvalidFactoryDep': __invalidFactoryDep,
  'resolveForwardRef': resolveForwardRef
};

const Type = Function;
function isType(v) {
  return typeof v === 'function';
}

const ES5_DELEGATE_CTOR = /^function\s+\S+\(\)\s*{[\s\S]+\.apply\(this,\s*(arguments|(?:[^()]+\(\[\],)?[^()]+\(arguments\).*)\)/;
const ES2015_INHERITED_CLASS = /^class\s+[A-Za-z\d$_]*\s*extends\s+[^{]+{/;
const ES2015_INHERITED_CLASS_WITH_CTOR = /^class\s+[A-Za-z\d$_]*\s*extends\s+[^{]+{[\s\S]*constructor\s*\(/;
const ES2015_INHERITED_CLASS_WITH_DELEGATE_CTOR = /^class\s+[A-Za-z\d$_]*\s*extends\s+[^{]+{[\s\S]*constructor\s*\(\)\s*{[^}]*super\(\.\.\.arguments\)/;
function isDelegateCtor(typeStr) {
  return ES5_DELEGATE_CTOR.test(typeStr) || ES2015_INHERITED_CLASS_WITH_DELEGATE_CTOR.test(typeStr) || ES2015_INHERITED_CLASS.test(typeStr) && !ES2015_INHERITED_CLASS_WITH_CTOR.test(typeStr);
}
class ReflectionCapabilities {
  _reflect;
  constructor(reflect) {
    this._reflect = reflect || _global['Reflect'];
  }
  factory(t) {
    return (...args) => new t(...args);
  }
  _zipTypesAndAnnotations(paramTypes, paramAnnotations) {
    let result;
    if (typeof paramTypes === 'undefined') {
      result = newArray(paramAnnotations.length);
    } else {
      result = newArray(paramTypes.length);
    }
    for (let i = 0; i < result.length; i++) {
      if (typeof paramTypes === 'undefined') {
        result[i] = [];
      } else if (paramTypes[i] && paramTypes[i] != Object) {
        result[i] = [paramTypes[i]];
      } else {
        result[i] = [];
      }
      if (paramAnnotations && paramAnnotations[i] != null) {
        result[i] = result[i].concat(paramAnnotations[i]);
      }
    }
    return result;
  }
  _ownParameters(type, parentCtor) {
    const typeStr = type.toString();
    if (isDelegateCtor(typeStr)) {
      return null;
    }
    if (type.parameters && type.parameters !== parentCtor.parameters) {
      return type.parameters;
    }
    const tsickleCtorParams = type.ctorParameters;
    if (tsickleCtorParams && tsickleCtorParams !== parentCtor.ctorParameters) {
      const ctorParameters = typeof tsickleCtorParams === 'function' ? tsickleCtorParams() : tsickleCtorParams;
      const paramTypes = ctorParameters.map(ctorParam => ctorParam && ctorParam.type);
      const paramAnnotations = ctorParameters.map(ctorParam => ctorParam && convertTsickleDecoratorIntoMetadata(ctorParam.decorators));
      return this._zipTypesAndAnnotations(paramTypes, paramAnnotations);
    }
    const paramAnnotations = Object.hasOwn(type, PARAMETERS) && type[PARAMETERS];
    const paramTypes = this._reflect && this._reflect.getOwnMetadata && this._reflect.getOwnMetadata('design:paramtypes', type);
    if (paramTypes || paramAnnotations) {
      return this._zipTypesAndAnnotations(paramTypes, paramAnnotations);
    }
    return newArray(type.length);
  }
  parameters(type) {
    if (!isType(type)) {
      return [];
    }
    const parentCtor = getParentCtor(type);
    let parameters = this._ownParameters(type, parentCtor);
    if (!parameters && parentCtor !== Object) {
      parameters = this.parameters(parentCtor);
    }
    return parameters || [];
  }
  _ownAnnotations(typeOrFunc, parentCtor) {
    if (typeOrFunc.annotations && typeOrFunc.annotations !== parentCtor.annotations) {
      let annotations = typeOrFunc.annotations;
      if (typeof annotations === 'function' && annotations.annotations) {
        annotations = annotations.annotations;
      }
      return annotations;
    }
    if (typeOrFunc.decorators && typeOrFunc.decorators !== parentCtor.decorators) {
      return convertTsickleDecoratorIntoMetadata(typeOrFunc.decorators);
    }
    if (Object.hasOwn(typeOrFunc, ANNOTATIONS)) {
      return typeOrFunc[ANNOTATIONS];
    }
    return null;
  }
  annotations(typeOrFunc) {
    if (!isType(typeOrFunc)) {
      return [];
    }
    const parentCtor = getParentCtor(typeOrFunc);
    const ownAnnotations = this._ownAnnotations(typeOrFunc, parentCtor) || [];
    const parentAnnotations = parentCtor !== Object ? this.annotations(parentCtor) : [];
    return parentAnnotations.concat(ownAnnotations);
  }
  _ownPropMetadata(typeOrFunc, parentCtor) {
    if (typeOrFunc.propMetadata && typeOrFunc.propMetadata !== parentCtor.propMetadata) {
      let propMetadata = typeOrFunc.propMetadata;
      if (typeof propMetadata === 'function' && propMetadata.propMetadata) {
        propMetadata = propMetadata.propMetadata;
      }
      return propMetadata;
    }
    if (typeOrFunc.propDecorators && typeOrFunc.propDecorators !== parentCtor.propDecorators) {
      const propDecorators = typeOrFunc.propDecorators;
      const propMetadata = {};
      Object.keys(propDecorators).forEach(prop => {
        propMetadata[prop] = convertTsickleDecoratorIntoMetadata(propDecorators[prop]);
      });
      return propMetadata;
    }
    if (Object.hasOwn(typeOrFunc, PROP_METADATA)) {
      return typeOrFunc[PROP_METADATA];
    }
    return null;
  }
  propMetadata(typeOrFunc) {
    if (!isType(typeOrFunc)) {
      return {};
    }
    const parentCtor = getParentCtor(typeOrFunc);
    const propMetadata = {};
    if (parentCtor !== Object) {
      const parentPropMetadata = this.propMetadata(parentCtor);
      Object.keys(parentPropMetadata).forEach(propName => {
        propMetadata[propName] = parentPropMetadata[propName];
      });
    }
    const ownPropMetadata = this._ownPropMetadata(typeOrFunc, parentCtor);
    if (ownPropMetadata) {
      Object.keys(ownPropMetadata).forEach(propName => {
        const decorators = [];
        if (Object.hasOwn(propMetadata, propName)) {
          decorators.push(...propMetadata[propName]);
        }
        decorators.push(...ownPropMetadata[propName]);
        propMetadata[propName] = decorators;
      });
    }
    return propMetadata;
  }
  ownPropMetadata(typeOrFunc) {
    if (!isType(typeOrFunc)) {
      return {};
    }
    return this._ownPropMetadata(typeOrFunc, getParentCtor(typeOrFunc)) || {};
  }
  hasLifecycleHook(type, lcProperty) {
    return type instanceof Type && lcProperty in type.prototype;
  }
}
function convertTsickleDecoratorIntoMetadata(decoratorInvocations) {
  if (!decoratorInvocations) {
    return [];
  }
  return decoratorInvocations.map(decoratorInvocation => {
    const decoratorType = decoratorInvocation.type;
    const annotationCls = decoratorType.annotationCls;
    const annotationArgs = decoratorInvocation.args ? decoratorInvocation.args : [];
    return new annotationCls(...annotationArgs);
  });
}
function getParentCtor(ctor) {
  const parentProto = ctor.prototype ? Object.getPrototypeOf(ctor.prototype) : null;
  const parentCtor = parentProto ? parentProto.constructor : null;
  return parentCtor || Object;
}

const Inject = attachInjectFlag(makeParamDecorator('Inject', token => ({
  token
})), -1);
const Optional = attachInjectFlag(makeParamDecorator('Optional'), 8);
const Self = attachInjectFlag(makeParamDecorator('Self'), 2);
const SkipSelf = attachInjectFlag(makeParamDecorator('SkipSelf'), 4);
const Host = attachInjectFlag(makeParamDecorator('Host'), 1);

const Attribute = makeParamDecorator('Attribute', attributeName => ({
  attributeName,
  __NG_ELEMENT_ID__: () => ɵɵinjectAttribute(attributeName)
}));

let _reflect = null;
function getReflect() {
  return _reflect = _reflect || new ReflectionCapabilities();
}
function reflectDependencies(type) {
  return convertDependencies(getReflect().parameters(type));
}
function convertDependencies(deps) {
  return deps.map(dep => reflectDependency(dep));
}
function reflectDependency(dep) {
  const meta = {
    token: null,
    attribute: null,
    host: false,
    optional: false,
    self: false,
    skipSelf: false
  };
  if (Array.isArray(dep) && dep.length > 0) {
    for (let j = 0; j < dep.length; j++) {
      const param = dep[j];
      if (param === undefined) {
        continue;
      }
      const proto = Object.getPrototypeOf(param);
      if (param instanceof Optional || proto.ngMetadataName === 'Optional') {
        meta.optional = true;
      } else if (param instanceof SkipSelf || proto.ngMetadataName === 'SkipSelf') {
        meta.skipSelf = true;
      } else if (param instanceof Self || proto.ngMetadataName === 'Self') {
        meta.self = true;
      } else if (param instanceof Host || proto.ngMetadataName === 'Host') {
        meta.host = true;
      } else if (param instanceof Inject) {
        meta.token = param.token;
      } else if (param instanceof Attribute) {
        if (param.attributeName === undefined) {
          throw new RuntimeError(-204, ngDevMode && `Attribute name must be defined.`);
        }
        meta.attribute = param.attributeName;
      } else {
        meta.token = param;
      }
    }
  } else if (dep === undefined || Array.isArray(dep) && dep.length === 0) {
    meta.token = null;
  } else {
    meta.token = dep;
  }
  return meta;
}

function compileInjectable(type, meta) {
  let ngInjectableDef = null;
  let ngFactoryDef = null;
  if (!Object.hasOwn(type, NG_PROV_DEF)) {
    Object.defineProperty(type, NG_PROV_DEF, {
      get: () => {
        if (ngInjectableDef === null) {
          const compiler = getCompilerFacade({
            usage: 0,
            kind: 'injectable',
            type
          });
          ngInjectableDef = compiler.compileInjectable(angularCoreDiEnv, `ng:///${type.name}/ɵprov.js`, getInjectableMetadata(type, meta));
        }
        return ngInjectableDef;
      }
    });
  }
  if (!Object.hasOwn(type, NG_FACTORY_DEF)) {
    Object.defineProperty(type, NG_FACTORY_DEF, {
      get: () => {
        if (ngFactoryDef === null) {
          const compiler = getCompilerFacade({
            usage: 0,
            kind: 'injectable',
            type
          });
          ngFactoryDef = compiler.compileFactory(angularCoreDiEnv, `ng:///${type.name}/ɵfac.js`, {
            name: type.name,
            type,
            typeArgumentCount: 0,
            deps: reflectDependencies(type),
            target: compiler.FactoryTarget.Injectable
          });
        }
        return ngFactoryDef;
      },
      configurable: true
    });
  }
}
const USE_VALUE = getClosureSafeProperty({
  provide: String,
  useValue: getClosureSafeProperty
});
function isUseClassProvider(meta) {
  return meta.useClass !== undefined;
}
function isUseValueProvider(meta) {
  return USE_VALUE in meta;
}
function isUseFactoryProvider(meta) {
  return meta.useFactory !== undefined;
}
function isUseExistingProvider(meta) {
  return meta.useExisting !== undefined;
}
function getInjectableMetadata(type, srcMeta) {
  const meta = srcMeta || {
    providedIn: null
  };
  const compilerMeta = {
    name: type.name,
    type: type,
    typeArgumentCount: 0,
    providedIn: meta.providedIn
  };
  if ((isUseClassProvider(meta) || isUseFactoryProvider(meta)) && meta.deps !== undefined) {
    compilerMeta.deps = convertDependencies(meta.deps);
  }
  if (isUseClassProvider(meta)) {
    compilerMeta.useClass = meta.useClass;
  } else if (isUseValueProvider(meta)) {
    compilerMeta.useValue = meta.useValue;
  } else if (isUseFactoryProvider(meta)) {
    compilerMeta.useFactory = meta.useFactory;
  } else if (isUseExistingProvider(meta)) {
    compilerMeta.useExisting = meta.useExisting;
  }
  return compilerMeta;
}

const Injectable = makeDecorator('Injectable', undefined, undefined, undefined, (type, meta) => compileInjectable(type, meta));

function compileService(type, meta) {
  let def = null;
  let factoryDef = null;
  if (!Object.hasOwn(type, NG_PROV_DEF)) {
    Object.defineProperty(type, NG_PROV_DEF, {
      get: () => {
        if (def === null) {
          const compiler = getCompilerFacade({
            usage: 0,
            kind: 'service',
            type
          });
          def = compiler.compileService(angularCoreDiEnv, `ng:///${type.name}/ɵprov.js`, getServiceMetadata(type, meta));
        }
        return def;
      }
    });
  }
  if (!Object.hasOwn(type, NG_FACTORY_DEF)) {
    Object.defineProperty(type, NG_FACTORY_DEF, {
      get: () => {
        if (factoryDef === null) {
          const compiler = getCompilerFacade({
            usage: 0,
            kind: 'service',
            type
          });
          factoryDef = compiler.compileFactory(angularCoreDiEnv, `ng:///${type.name}/ɵfac.js`, {
            name: type.name,
            type,
            typeArgumentCount: 0,
            deps: reflectDependencies(type),
            target: compiler.FactoryTarget.Service
          });
        }
        return factoryDef;
      },
      configurable: true
    });
  }
}
function getServiceMetadata(type, srcMeta) {
  const compilerMeta = {
    name: type.name,
    type: type,
    typeArgumentCount: 0,
    autoProvided: srcMeta?.autoProvided,
    factory: srcMeta?.factory
  };
  return compilerMeta;
}

const Service = makeDecorator('Service', undefined, undefined, undefined, (type, meta) => compileService(type, meta));

function injectElementRef() {
  return createElementRef(getCurrentTNode(), getLView());
}
function createElementRef(tNode, lView) {
  return new ElementRef(getNativeByTNode(tNode, lView));
}
class ElementRef {
  nativeElement;
  constructor(nativeElement) {
    this.nativeElement = nativeElement;
  }
  static __NG_ELEMENT_ID__ = injectElementRef;
}
if (typeof ngDevMode === 'undefined' || ngDevMode) {
  registerSpecialProvider(ElementRef);
}
function unwrapElementRef(value) {
  return value instanceof ElementRef ? value.nativeElement : value;
}

function symbolIterator() {
  return this._results[Symbol.iterator]();
}
class QueryList {
  _emitDistinctChangesOnly;
  dirty = true;
  _onDirty = undefined;
  _results = [];
  _changesDetected = false;
  _changes = undefined;
  length = 0;
  first = undefined;
  last = undefined;
  get changes() {
    return this._changes ??= new Subject();
  }
  constructor(_emitDistinctChangesOnly = false) {
    this._emitDistinctChangesOnly = _emitDistinctChangesOnly;
  }
  get(index) {
    return this._results[index];
  }
  map(fn) {
    return this._results.map(fn);
  }
  filter(fn) {
    return this._results.filter(fn);
  }
  find(fn) {
    return this._results.find(fn);
  }
  reduce(fn, init) {
    return this._results.reduce(fn, init);
  }
  forEach(fn) {
    this._results.forEach(fn);
  }
  some(fn) {
    return this._results.some(fn);
  }
  toArray() {
    return this._results.slice();
  }
  toString() {
    return this._results.toString();
  }
  reset(resultsTree, identityAccessor) {
    this.dirty = false;
    const newResultFlat = flatten(resultsTree);
    if (this._changesDetected = !arrayEquals(this._results, newResultFlat, identityAccessor)) {
      this._results = newResultFlat;
      this.length = newResultFlat.length;
      this.last = newResultFlat[this.length - 1];
      this.first = newResultFlat[0];
    }
  }
  notifyOnChanges() {
    if (this._changes !== undefined && (this._changesDetected || !this._emitDistinctChangesOnly)) this._changes.next(this);
  }
  onDirty(cb) {
    this._onDirty = cb;
  }
  setDirty() {
    this.dirty = true;
    this._onDirty?.();
  }
  destroy() {
    if (this._changes !== undefined) {
      this._changes.complete();
      this._changes.unsubscribe();
    }
  }
  [Symbol.iterator] = (() => symbolIterator)();
}

const SKIP_HYDRATION_ATTR_NAME = 'ngSkipHydration';
const SKIP_HYDRATION_ATTR_NAME_LOWER_CASE = 'ngskiphydration';
function hasSkipHydrationAttrOnTNode(tNode) {
  const attrs = tNode.mergedAttrs;
  if (attrs === null) return false;
  for (let i = 0; i < attrs.length; i += 2) {
    const value = attrs[i];
    if (typeof value === 'number') return false;
    if (typeof value === 'string' && value.toLowerCase() === SKIP_HYDRATION_ATTR_NAME_LOWER_CASE) {
      return true;
    }
  }
  return false;
}
function hasSkipHydrationAttrOnRElement(rNode) {
  return rNode.hasAttribute(SKIP_HYDRATION_ATTR_NAME);
}
function hasInSkipHydrationBlockFlag(tNode) {
  return (tNode.flags & 128) === 128;
}
function isInSkipHydrationBlock(tNode) {
  if (hasInSkipHydrationBlockFlag(tNode)) {
    return true;
  }
  let currentTNode = tNode.parent;
  while (currentTNode) {
    if (hasInSkipHydrationBlockFlag(tNode) || hasSkipHydrationAttrOnTNode(currentTNode)) {
      return true;
    }
    currentTNode = currentTNode.parent;
  }
  return false;
}
function isI18nInSkipHydrationBlock(parentTNode) {
  return hasInSkipHydrationBlockFlag(parentTNode) || hasSkipHydrationAttrOnTNode(parentTNode) || isInSkipHydrationBlock(parentTNode);
}

var ChangeDetectionStrategy;
(function (ChangeDetectionStrategy) {
  ChangeDetectionStrategy[ChangeDetectionStrategy["OnPush"] = 0] = "OnPush";
  ChangeDetectionStrategy[ChangeDetectionStrategy["Eager"] = 1] = "Eager";
  ChangeDetectionStrategy[ChangeDetectionStrategy["Default"] = 1] = "Default";
})(ChangeDetectionStrategy || (ChangeDetectionStrategy = {}));

const TRACKED_LVIEWS = new Map();
let uniqueIdCounter = 0;
function getUniqueLViewId() {
  return uniqueIdCounter++;
}
function registerLView(lView) {
  ngDevMode && assertNumber(lView[ID], 'LView must have an ID in order to be registered');
  TRACKED_LVIEWS.set(lView[ID], lView);
}
function getLViewById(id) {
  ngDevMode && assertNumber(id, 'ID used for LView lookup must be a number');
  return TRACKED_LVIEWS.get(id) || null;
}
function unregisterLView(lView) {
  ngDevMode && assertNumber(lView[ID], 'Cannot stop tracking an LView that does not have an ID');
  TRACKED_LVIEWS.delete(lView[ID]);
}
function getTrackedLViews() {
  return TRACKED_LVIEWS;
}

class LContext {
  lViewId;
  nodeIndex;
  native;
  component;
  directives;
  localRefs;
  get lView() {
    return getLViewById(this.lViewId);
  }
  constructor(lViewId, nodeIndex, native) {
    this.lViewId = lViewId;
    this.nodeIndex = nodeIndex;
    this.native = native;
  }
}

function getLContext(target) {
  let mpValue = readPatchedData(target);
  if (mpValue) {
    if (isLView(mpValue)) {
      const lView = mpValue;
      let nodeIndex;
      let component = undefined;
      let directives = undefined;
      if (isComponentInstance(target)) {
        nodeIndex = findViaComponent(lView, target);
        if (nodeIndex == -1) {
          throw new Error('The provided component was not found in the application');
        }
        component = target;
      } else if (isDirectiveInstance(target)) {
        nodeIndex = findViaDirective(lView, target);
        if (nodeIndex == -1) {
          throw new Error('The provided directive was not found in the application');
        }
        directives = getDirectivesAtNodeIndex(nodeIndex, lView);
      } else {
        nodeIndex = findViaNativeElement(lView, target);
        if (nodeIndex == -1) {
          return null;
        }
      }
      const native = unwrapRNode(lView[nodeIndex]);
      const existingCtx = readPatchedData(native);
      const context = existingCtx && !Array.isArray(existingCtx) ? existingCtx : createLContext(lView, nodeIndex, native);
      if (component && context.component === undefined) {
        context.component = component;
        attachPatchData(context.component, context);
      }
      if (directives && context.directives === undefined) {
        context.directives = directives;
        for (let i = 0; i < directives.length; i++) {
          attachPatchData(directives[i], context);
        }
      }
      attachPatchData(context.native, context);
      mpValue = context;
    }
  } else {
    const rElement = target;
    ngDevMode && assertDomNode(rElement);
    let parent = rElement;
    while (parent = parent.parentNode) {
      const parentContext = readPatchedData(parent);
      if (parentContext) {
        const lView = Array.isArray(parentContext) ? parentContext : parentContext.lView;
        if (!lView) {
          return null;
        }
        const index = findViaNativeElement(lView, rElement);
        if (index >= 0) {
          const native = unwrapRNode(lView[index]);
          const context = createLContext(lView, index, native);
          attachPatchData(native, context);
          mpValue = context;
          break;
        }
      }
    }
  }
  return mpValue || null;
}
function createLContext(lView, nodeIndex, native) {
  return new LContext(lView[ID], nodeIndex, native);
}
function getComponentViewByInstance(componentInstance) {
  let patchedData = readPatchedData(componentInstance);
  let lView;
  if (isLView(patchedData)) {
    const contextLView = patchedData;
    const nodeIndex = findViaComponent(contextLView, componentInstance);
    lView = getComponentLViewByIndex(nodeIndex, contextLView);
    const context = createLContext(contextLView, nodeIndex, lView[HOST]);
    context.component = componentInstance;
    attachPatchData(componentInstance, context);
    attachPatchData(context.native, context);
  } else {
    const context = patchedData;
    const contextLView = context.lView;
    ngDevMode && assertLView(contextLView);
    lView = getComponentLViewByIndex(context.nodeIndex, contextLView);
  }
  return lView;
}
const MONKEY_PATCH_KEY_NAME = '__ngContext__';
function attachPatchData(target, data) {
  ngDevMode && assertDefined(target, 'Target expected');
  if (isLView(data)) {
    target[MONKEY_PATCH_KEY_NAME] = data[ID];
    registerLView(data);
  } else {
    target[MONKEY_PATCH_KEY_NAME] = data;
  }
}
function readPatchedData(target) {
  ngDevMode && assertDefined(target, 'Target expected');
  const data = target[MONKEY_PATCH_KEY_NAME];
  return typeof data === 'number' ? getLViewById(data) : data || null;
}
function readPatchedLView(target) {
  const value = readPatchedData(target);
  if (value) {
    return isLView(value) ? value : value.lView;
  }
  return null;
}
function isComponentInstance(instance) {
  return instance && instance.constructor && instance.constructor.ɵcmp;
}
function isDirectiveInstance(instance) {
  return instance && instance.constructor && instance.constructor.ɵdir;
}
function findViaNativeElement(lView, target) {
  const tView = lView[TVIEW$1];
  for (let i = HEADER_OFFSET; i < tView.bindingStartIndex; i++) {
    if (unwrapRNode(lView[i]) === target) {
      return i;
    }
  }
  return -1;
}
function traverseNextElement(tNode) {
  if (tNode.child) {
    return tNode.child;
  } else if (tNode.next) {
    return tNode.next;
  } else {
    while (tNode.parent && !tNode.parent.next) {
      tNode = tNode.parent;
    }
    return tNode.parent && tNode.parent.next;
  }
}
function findViaComponent(lView, componentInstance) {
  const componentIndices = lView[TVIEW$1].components;
  if (componentIndices) {
    for (let i = 0; i < componentIndices.length; i++) {
      const elementComponentIndex = componentIndices[i];
      const componentView = getComponentLViewByIndex(elementComponentIndex, lView);
      if (componentView[CONTEXT] === componentInstance) {
        return elementComponentIndex;
      }
    }
  } else {
    const rootComponentView = getComponentLViewByIndex(HEADER_OFFSET, lView);
    const rootComponent = rootComponentView[CONTEXT];
    if (rootComponent === componentInstance) {
      return HEADER_OFFSET;
    }
  }
  return -1;
}
function findViaDirective(lView, directiveInstance) {
  let tNode = lView[TVIEW$1].firstChild;
  while (tNode) {
    const directiveIndexStart = tNode.directiveStart;
    const directiveIndexEnd = tNode.directiveEnd;
    for (let i = directiveIndexStart; i < directiveIndexEnd; i++) {
      if (lView[i] === directiveInstance) {
        return tNode.index;
      }
    }
    tNode = traverseNextElement(tNode);
  }
  return -1;
}
function getDirectivesAtNodeIndex(nodeIndex, lView) {
  const tNode = lView[TVIEW$1].data[nodeIndex];
  if (tNode.directiveStart === 0) return EMPTY_ARRAY;
  const results = [];
  for (let i = tNode.directiveStart; i < tNode.directiveEnd; i++) {
    const directiveInstance = lView[i];
    if (!isComponentInstance(directiveInstance)) {
      results.push(directiveInstance);
    }
  }
  return results;
}
function getComponentAtNodeIndex(nodeIndex, lView) {
  const tNode = lView[TVIEW$1].data[nodeIndex];
  return isComponentHost(tNode) ? lView[tNode.directiveStart + tNode.componentOffset] : null;
}
function discoverLocalRefs(lView, nodeIndex) {
  const tNode = lView[TVIEW$1].data[nodeIndex];
  if (tNode && tNode.localNames) {
    const result = {};
    let localIndex = tNode.index + 1;
    for (let i = 0; i < tNode.localNames.length; i += 2) {
      result[tNode.localNames[i]] = lView[localIndex];
      localIndex++;
    }
    return result;
  }
  return null;
}

function getRootView(componentOrLView) {
  ngDevMode && assertDefined(componentOrLView, 'component');
  let lView = isLView(componentOrLView) ? componentOrLView : readPatchedLView(componentOrLView);
  while (lView && !isRootView(lView)) {
    lView = getLViewParent(lView);
  }
  ngDevMode && assertLView(lView);
  return lView;
}
function getRootContext(viewOrComponent) {
  const rootView = getRootView(viewOrComponent);
  ngDevMode && assertDefined(rootView[CONTEXT], 'Root view has no context. Perhaps it is disconnected?');
  return rootView[CONTEXT];
}
function getFirstLContainer(lView) {
  return getNearestLContainer(lView[CHILD_HEAD]);
}
function getNextLContainer(container) {
  return getNearestLContainer(container[NEXT]);
}
function getNearestLContainer(viewOrContainer) {
  while (viewOrContainer !== null && !isLContainer(viewOrContainer)) {
    viewOrContainer = viewOrContainer[NEXT];
  }
  return viewOrContainer;
}
function* walkLViewChildren(tNode, lView) {
  let child = tNode.child;
  while (child) {
    yield [child, lView];
    child = child.next;
  }
  if (tNode.componentOffset > -1) {
    const componentLView = getComponentLViewByIndex(tNode.index, lView);
    if (isLView(componentLView)) {
      const componentTView = componentLView[TVIEW$1];
      let componentChild = componentTView.firstChild;
      while (componentChild) {
        yield [componentChild, componentLView];
        componentChild = componentChild.next;
      }
    }
  }
  const slot = lView[tNode.index];
  if (isLContainer(slot)) {
    for (let i = CONTAINER_HEADER_OFFSET; i < slot.length; i++) {
      const embeddedLView = slot[i];
      const embeddedTView = embeddedLView[TVIEW$1];
      let embeddedChild = embeddedTView.firstChild;
      while (embeddedChild) {
        yield [embeddedChild, embeddedLView];
        embeddedChild = embeddedChild.next;
      }
    }
  }
}
function* walkLViewDescendants(lView) {
  const tView = lView[TVIEW$1];
  let child = tView.firstChild;
  while (child) {
    yield* walkTNodeDescendants(child, lView);
    child = child.next;
  }
}
function* walkTNodeDescendants(tNode, lView) {
  yield [tNode, lView];
  for (const [childTNode, childLView] of walkLViewChildren(tNode, lView)) {
    yield* walkTNodeDescendants(childTNode, childLView);
  }
}
function* walkLViewDirectives(lView) {
  for (const [tNode, currentLView] of walkLViewDescendants(lView)) {
    if (tNode.directiveEnd > tNode.directiveStart) {
      yield [tNode, currentLView];
    }
  }
}

function getComponent(element) {
  ngDevMode && assertDomElement(element);
  const context = getLContext(element);
  if (context === null) return null;
  if (context.component === undefined) {
    const lView = context.lView;
    if (lView === null) {
      return null;
    }
    context.component = getComponentAtNodeIndex(context.nodeIndex, lView);
  }
  return context.component;
}
function getContext(element) {
  assertDomElement(element);
  const context = getLContext(element);
  const lView = context ? context.lView : null;
  return lView === null ? null : lView[CONTEXT];
}
function getOwningComponent(elementOrDir) {
  const context = getLContext(elementOrDir);
  let lView = context ? context.lView : null;
  if (lView === null) return null;
  let parent;
  while (lView[TVIEW$1].type === 2 && (parent = getLViewParent(lView))) {
    lView = parent;
  }
  return isRootView(lView) ? null : lView[CONTEXT];
}
function getRootComponents(elementOrDir) {
  const lView = readPatchedLView(elementOrDir);
  return lView !== null ? [getRootContext(lView)] : [];
}
function getInjector(elementOrDir) {
  const context = getLContext(elementOrDir);
  const lView = context ? context.lView : null;
  if (lView === null) return Injector.NULL;
  const tNode = lView[TVIEW$1].data[context.nodeIndex];
  return new NodeInjector(tNode, lView);
}
function getInjectionTokens(element) {
  const context = getLContext(element);
  const lView = context ? context.lView : null;
  if (lView === null) return [];
  const tView = lView[TVIEW$1];
  const tNode = tView.data[context.nodeIndex];
  const providerTokens = [];
  const startIndex = tNode.providerIndexes & 1048575;
  const endIndex = tNode.directiveEnd;
  for (let i = startIndex; i < endIndex; i++) {
    let value = tView.data[i];
    if (isDirectiveDefHack(value)) {
      value = value.type;
    }
    providerTokens.push(value);
  }
  return providerTokens;
}
function getDirectives(node) {
  if (node instanceof Text) {
    return [];
  }
  const context = getLContext(node);
  const lView = context ? context.lView : null;
  if (lView === null) {
    return [];
  }
  const tView = lView[TVIEW$1];
  const nodeIndex = context.nodeIndex;
  if (!tView?.data[nodeIndex]) {
    return [];
  }
  if (context.directives === undefined) {
    context.directives = getDirectivesAtNodeIndex(nodeIndex, lView);
  }
  return context.directives === null ? [] : [...context.directives];
}
var AcxChangeDetectionStrategy;
(function (AcxChangeDetectionStrategy) {
  AcxChangeDetectionStrategy[AcxChangeDetectionStrategy["Default"] = 0] = "Default";
  AcxChangeDetectionStrategy[AcxChangeDetectionStrategy["OnPush"] = 1] = "OnPush";
})(AcxChangeDetectionStrategy || (AcxChangeDetectionStrategy = {}));
var AcxViewEncapsulation;
(function (AcxViewEncapsulation) {
  AcxViewEncapsulation[AcxViewEncapsulation["Emulated"] = 0] = "Emulated";
  AcxViewEncapsulation[AcxViewEncapsulation["None"] = 1] = "None";
})(AcxViewEncapsulation || (AcxViewEncapsulation = {}));
function getDirectiveMetadata$1(directiveOrComponentInstance) {
  if (!directiveOrComponentInstance) {
    return null;
  }
  const {
    constructor
  } = directiveOrComponentInstance;
  if (!constructor) {
    throw new Error('Unable to find the instance constructor');
  }
  const componentDef = getComponentDef(constructor);
  if (componentDef) {
    const inputs = extractInputDebugMetadata(componentDef.inputs);
    return {
      inputs,
      outputs: componentDef.outputs,
      encapsulation: componentDef.encapsulation,
      changeDetection: componentDef.onPush ? ChangeDetectionStrategy.OnPush : ChangeDetectionStrategy.Eager
    };
  }
  const directiveDef = getDirectiveDef(constructor);
  if (directiveDef) {
    const inputs = extractInputDebugMetadata(directiveDef.inputs);
    return {
      inputs,
      outputs: directiveDef.outputs
    };
  }
  return null;
}
function getLocalRefs(target) {
  const context = getLContext(target);
  if (context === null) return {};
  if (context.localRefs === undefined) {
    const lView = context.lView;
    if (lView === null) {
      return {};
    }
    context.localRefs = discoverLocalRefs(lView, context.nodeIndex);
  }
  return context.localRefs || {};
}
function getHostElement(componentOrDirective) {
  return getLContext(componentOrDirective).native;
}
function getListeners(element) {
  ngDevMode && assertDomElement(element);
  const lContext = getLContext(element);
  const lView = lContext === null ? null : lContext.lView;
  if (lView === null) return [];
  const tView = lView[TVIEW$1];
  const lCleanup = lView[CLEANUP];
  const tCleanup = tView.cleanup;
  const listeners = [];
  if (tCleanup && lCleanup) {
    for (let i = 0; i < tCleanup.length;) {
      const firstParam = tCleanup[i++];
      const secondParam = tCleanup[i++];
      if (typeof firstParam === 'string') {
        const name = firstParam;
        const listenerElement = unwrapRNode(lView[secondParam]);
        const callback = lCleanup[tCleanup[i++]];
        const useCaptureOrIndx = tCleanup[i++];
        const type = typeof useCaptureOrIndx === 'boolean' || useCaptureOrIndx >= 0 ? 'dom' : 'output';
        const useCapture = typeof useCaptureOrIndx === 'boolean' ? useCaptureOrIndx : false;
        if (element == listenerElement) {
          listeners.push({
            element,
            name,
            callback,
            useCapture,
            type
          });
        }
      }
    }
  }
  listeners.sort(sortListeners);
  return listeners;
}
function sortListeners(a, b) {
  if (a.name == b.name) return 0;
  return a.name < b.name ? -1 : 1;
}
function isDirectiveDefHack(obj) {
  return obj.type !== undefined && obj.declaredInputs !== undefined && obj.resolveHostDirectives !== undefined;
}
function assertDomElement(value) {
  if (typeof Element !== 'undefined' && !(value instanceof Element)) {
    throw new Error('Expecting instance of DOM Element');
  }
}
function extractInputDebugMetadata(inputs) {
  const res = {};
  for (const key in inputs) {
    if (Object.hasOwn(inputs, key)) {
      const value = inputs[key];
      if (value !== undefined) {
        res[key] = value[0];
      }
    }
  }
  return res;
}

let DOCUMENT = undefined;
function setDocument(document) {
  DOCUMENT = document;
}
function getDocument() {
  if (DOCUMENT !== undefined) {
    return DOCUMENT;
  } else if (typeof document !== 'undefined') {
    return document;
  }
  throw new RuntimeError(210, (typeof ngDevMode === 'undefined' || ngDevMode) && `The document object is not available in this context. Make sure the DOCUMENT injection token is provided.`);
}

const REFERENCE_NODE_HOST = 'h';
const REFERENCE_NODE_BODY = 'b';
const NODE_NAVIGATION_STEP_FIRST_CHILD = 'f';
const NODE_NAVIGATION_STEP_NEXT_SIBLING = 'n';
const ELEMENT_CONTAINERS = 'e';
const TEMPLATES = 't';
const CONTAINERS = 'c';
const MULTIPLIER = 'x';
const NUM_ROOT_NODES = 'r';
const TEMPLATE_ID = 'i';
const NODES = 'n';
const DISCONNECTED_NODES = 'd';
const I18N_DATA = 'l';
const DEFER_BLOCK_ID = 'di';
const DEFER_BLOCK_STATE$1 = 's';
const DEFER_PARENT_BLOCK_ID = 'p';
const DEFER_HYDRATE_TRIGGERS = 't';

const IS_HYDRATION_DOM_REUSE_ENABLED = new InjectionToken(typeof ngDevMode === 'undefined' || ngDevMode ? 'IS_HYDRATION_DOM_REUSE_ENABLED' : '');
const PRESERVE_HOST_CONTENT_DEFAULT = false;
const PRESERVE_HOST_CONTENT = new InjectionToken(typeof ngDevMode === 'undefined' || ngDevMode ? 'PRESERVE_HOST_CONTENT' : '', {
  factory: () => PRESERVE_HOST_CONTENT_DEFAULT
});
const IS_I18N_HYDRATION_ENABLED = new InjectionToken(typeof ngDevMode === 'undefined' || ngDevMode ? 'IS_I18N_HYDRATION_ENABLED' : '');
const IS_EVENT_REPLAY_ENABLED = new InjectionToken(typeof ngDevMode === 'undefined' || ngDevMode ? 'IS_EVENT_REPLAY_ENABLED' : '');
const EVENT_REPLAY_ENABLED_DEFAULT = false;
const EVENT_REPLAY_QUEUE = new InjectionToken(typeof ngDevMode !== 'undefined' && ngDevMode ? 'EVENT_REPLAY_QUEUE' : '', {
  factory: () => []
});
const IS_INCREMENTAL_HYDRATION_ENABLED = new InjectionToken(typeof ngDevMode === 'undefined' || ngDevMode ? 'IS_INCREMENTAL_HYDRATION_ENABLED' : '');
const JSACTION_BLOCK_ELEMENT_MAP = new InjectionToken(typeof ngDevMode !== 'undefined' && ngDevMode ? 'JSACTION_BLOCK_ELEMENT_MAP' : '', {
  factory: () => new Map()
});
const IS_ENABLED_BLOCKING_INITIAL_NAVIGATION = new InjectionToken(typeof ngDevMode === 'undefined' || ngDevMode ? 'IS_ENABLED_BLOCKING_INITIAL_NAVIGATION' : '');

const eventListenerOptions = {
  passive: true,
  capture: true
};
const hoverTriggers = new WeakMap();
const interactionTriggers = new WeakMap();
const viewportTriggers = new WeakMap();
const interactionEventNames = ['click', 'keydown'];
const hoverEventNames = ['mouseenter', 'mouseover', 'focusin'];
const intersectionObservers = new Map();
class DeferEventEntry {
  callbacks = new Set();
  listener = () => {
    for (const callback of this.callbacks) {
      callback();
    }
  };
}
function onInteraction(trigger, callback) {
  let entry = interactionTriggers.get(trigger);
  if (!entry) {
    entry = new DeferEventEntry();
    interactionTriggers.set(trigger, entry);
    for (const name of interactionEventNames) {
      trigger.addEventListener(name, entry.listener, eventListenerOptions);
    }
  }
  entry.callbacks.add(callback);
  return () => {
    const {
      callbacks,
      listener
    } = entry;
    callbacks.delete(callback);
    if (callbacks.size === 0) {
      interactionTriggers.delete(trigger);
      for (const name of interactionEventNames) {
        trigger.removeEventListener(name, listener, eventListenerOptions);
      }
    }
  };
}
function onHover(trigger, callback) {
  let entry = hoverTriggers.get(trigger);
  if (!entry) {
    entry = new DeferEventEntry();
    hoverTriggers.set(trigger, entry);
    for (const name of hoverEventNames) {
      trigger.addEventListener(name, entry.listener, eventListenerOptions);
    }
  }
  entry.callbacks.add(callback);
  return () => {
    const {
      callbacks,
      listener
    } = entry;
    callbacks.delete(callback);
    if (callbacks.size === 0) {
      for (const name of hoverEventNames) {
        trigger.removeEventListener(name, listener, eventListenerOptions);
      }
      hoverTriggers.delete(trigger);
    }
  };
}
function createIntersectionObserver(options) {
  const key = getIntersectionObserverKey(options);
  return new IntersectionObserver(entries => {
    for (const current of entries) {
      if (current.isIntersecting && viewportTriggers.has(current.target)) {
        viewportTriggers.get(current.target)?.get(key)?.listener();
      }
    }
  }, options);
}
function onViewport(trigger, callback, observerFactoryFn, options) {
  const key = getIntersectionObserverKey(options);
  let entry = viewportTriggers.get(trigger)?.get(key);
  if (!intersectionObservers.has(key)) {
    intersectionObservers.set(key, {
      observer: observerFactoryFn(options),
      count: 0
    });
  }
  const config = intersectionObservers.get(key);
  if (!entry) {
    entry = new DeferEventEntry();
    config.observer.observe(trigger);
    let triggerConfig = viewportTriggers.get(trigger);
    if (triggerConfig) {
      triggerConfig.set(key, entry);
    } else {
      triggerConfig = new Map();
      viewportTriggers.set(trigger, triggerConfig);
    }
    triggerConfig.set(key, entry);
    config.count++;
  }
  entry.callbacks.add(callback);
  return () => {
    if (!viewportTriggers.get(trigger)?.has(key)) {
      return;
    }
    entry.callbacks.delete(callback);
    if (entry.callbacks.size === 0) {
      config.observer.unobserve(trigger);
      config.count--;
      const triggerConfig = viewportTriggers.get(trigger);
      if (triggerConfig) {
        triggerConfig.delete(key);
        if (triggerConfig.size === 0) {
          viewportTriggers.delete(trigger);
        }
      }
    }
    if (config.count === 0) {
      config.observer.disconnect();
      intersectionObservers.delete(key);
    }
  };
}
function getIntersectionObserverKey(options) {
  if (!options) {
    return '';
  }
  return `${options.rootMargin}/${typeof options.threshold === 'number' ? options.threshold : options.threshold?.join('\n')}`;
}

const DEFER_BLOCK_SSR_ID_ATTRIBUTE = 'ngb';
function setJSActionAttributes(nativeElement, eventTypes, parentDeferBlockId = null) {
  if (eventTypes.length === 0 || nativeElement.nodeType !== Node.ELEMENT_NODE) {
    return;
  }
  const existingAttr = nativeElement.getAttribute(Attribute$1.JSACTION);
  const parts = eventTypes.reduce((prev, curr) => {
    return (existingAttr?.indexOf(curr) ?? -1) === -1 ? prev + curr + ':;' : prev;
  }, '');
  nativeElement.setAttribute(Attribute$1.JSACTION, `${existingAttr ?? ''}${parts}`);
  const blockName = parentDeferBlockId ?? '';
  if (blockName !== '' && parts.length > 0) {
    nativeElement.setAttribute(DEFER_BLOCK_SSR_ID_ATTRIBUTE, blockName);
  }
}
const sharedStashFunction = (rEl, eventType, listenerFn) => {
  const el = rEl;
  const eventListenerMap = el.__jsaction_fns ?? new Map();
  const eventListeners = eventListenerMap.get(eventType) ?? [];
  eventListeners.push(listenerFn);
  eventListenerMap.set(eventType, eventListeners);
  el.__jsaction_fns = eventListenerMap;
};
const sharedMapFunction = (rEl, jsActionMap) => {
  const el = rEl;
  let blockName = el.getAttribute(DEFER_BLOCK_SSR_ID_ATTRIBUTE) ?? '';
  const blockSet = jsActionMap.get(blockName) ?? new Set();
  if (!blockSet.has(el)) {
    blockSet.add(el);
  }
  jsActionMap.set(blockName, blockSet);
};
function removeListenersFromBlocks(blockNames, jsActionMap) {
  if (blockNames.length > 0) {
    let blockList = [];
    for (let blockName of blockNames) {
      if (jsActionMap.has(blockName)) {
        blockList = [...blockList, ...jsActionMap.get(blockName)];
      }
    }
    const replayList = new Set(blockList);
    replayList.forEach(removeListeners);
  }
}
const removeListeners = el => {
  el.removeAttribute(Attribute$1.JSACTION);
  el.removeAttribute(DEFER_BLOCK_SSR_ID_ATTRIBUTE);
  el.__jsaction_fns = undefined;
};
const JSACTION_EVENT_CONTRACT = new InjectionToken(typeof ngDevMode !== 'undefined' && ngDevMode ? 'EVENT_CONTRACT_DETAILS' : '', {
  factory: () => ({})
});
const handledEventElements = new WeakMap();
function markEventHandledForElement(event, element) {
  if (event == null || typeof event !== 'object') return;
  let elements = handledEventElements.get(event);
  if (!elements) {
    elements = new WeakSet();
    handledEventElements.set(event, elements);
  }
  elements.add(element);
}
function invokeListeners(event, currentTarget) {
  const handlerFns = currentTarget?.__jsaction_fns?.get(event.type);
  if (!handlerFns || !currentTarget?.isConnected) {
    return;
  }
  if (currentTarget && handledEventElements.get(event)?.has(currentTarget)) {
    return;
  }
  for (const handler of handlerFns) {
    handler(event);
  }
}
const stashEventListeners = new Map();
function setStashFn(appId, fn) {
  stashEventListeners.set(appId, fn);
  return () => stashEventListeners.delete(appId);
}
let isStashEventListenerImplEnabled = false;
let _stashEventListenerImpl = (lView, target, eventName, wrappedListener) => {};
function stashEventListenerImpl(lView, target, eventName, wrappedListener) {
  _stashEventListenerImpl(lView, target, eventName, wrappedListener);
}
function enableStashEventListenerImpl() {
  if (!isStashEventListenerImplEnabled) {
    _stashEventListenerImpl = (lView, target, eventName, wrappedListener) => {
      const appId = lView[INJECTOR].get(APP_ID);
      const stashEventListener = stashEventListeners.get(appId);
      stashEventListener?.(target, eventName, wrappedListener);
    };
    isStashEventListenerImplEnabled = true;
  }
}

const DEHYDRATED_BLOCK_REGISTRY = new InjectionToken(typeof ngDevMode !== 'undefined' && ngDevMode ? 'DEHYDRATED_BLOCK_REGISTRY' : '');
class DehydratedBlockRegistry {
  registry = new Map();
  cleanupFns = new Map();
  jsActionMap = inject(JSACTION_BLOCK_ELEMENT_MAP);
  contract = inject(JSACTION_EVENT_CONTRACT);
  add(blockId, info) {
    this.registry.set(blockId, info);
    if (this.awaitingCallbacks.has(blockId)) {
      const awaitingCallbacks = this.awaitingCallbacks.get(blockId);
      for (const cb of awaitingCallbacks) {
        cb();
      }
    }
  }
  get(blockId) {
    return this.registry.get(blockId) ?? null;
  }
  has(blockId) {
    return this.registry.has(blockId);
  }
  cleanup(hydratedBlocks) {
    removeListenersFromBlocks(hydratedBlocks, this.jsActionMap);
    for (let blockId of hydratedBlocks) {
      this.registry.delete(blockId);
      this.jsActionMap.delete(blockId);
      this.invokeTriggerCleanupFns(blockId);
      this.hydrating.delete(blockId);
      this.awaitingCallbacks.delete(blockId);
    }
    if (this.size === 0) {
      this.contract.instance?.cleanUp();
    }
  }
  get size() {
    return this.registry.size;
  }
  addCleanupFn(blockId, fn) {
    let cleanupFunctions = [];
    if (this.cleanupFns.has(blockId)) {
      cleanupFunctions = this.cleanupFns.get(blockId);
    }
    cleanupFunctions.push(fn);
    this.cleanupFns.set(blockId, cleanupFunctions);
  }
  invokeTriggerCleanupFns(blockId) {
    const fns = this.cleanupFns.get(blockId) ?? [];
    for (let fn of fns) {
      fn();
    }
    this.cleanupFns.delete(blockId);
  }
  hydrating = new Map();
  awaitingCallbacks = new Map();
  awaitParentBlock(topmostParentBlock, callback) {
    const parentBlockAwaitCallbacks = this.awaitingCallbacks.get(topmostParentBlock) ?? [];
    parentBlockAwaitCallbacks.push(callback);
    this.awaitingCallbacks.set(topmostParentBlock, parentBlockAwaitCallbacks);
  }
  static ɵprov =
  /* @__PURE__ */
  __defineInjectable({
    token: DehydratedBlockRegistry,
    providedIn: null,
    factory: () => new DehydratedBlockRegistry()
  });
}

function isDetachedByI18n(tNode) {
  return (tNode.flags & 32) === 32;
}

const TRANSFER_STATE_TOKEN_ID = '__nghData__';
const NGH_DATA_KEY = makeStateKey(TRANSFER_STATE_TOKEN_ID);
const TRANSFER_STATE_DEFER_BLOCKS_INFO = '__nghDeferData__';
const NGH_DEFER_BLOCKS_KEY = makeStateKey(TRANSFER_STATE_DEFER_BLOCKS_INFO);
function isInternalHydrationTransferStateKey(key) {
  return key === TRANSFER_STATE_TOKEN_ID || key === TRANSFER_STATE_DEFER_BLOCKS_INFO;
}
const NGH_ATTR_NAME = 'ngh';
const SSR_CONTENT_INTEGRITY_MARKER = 'nghm';
let _retrieveHydrationInfoImpl = () => null;
function retrieveHydrationInfoImpl(rNode, injector, isRootView = false) {
  let nghAttrValue = rNode.getAttribute(NGH_ATTR_NAME);
  if (nghAttrValue == null) return null;
  const [componentViewNgh, rootViewNgh] = nghAttrValue.split('|');
  nghAttrValue = isRootView ? rootViewNgh : componentViewNgh;
  if (!nghAttrValue) return null;
  const rootNgh = rootViewNgh ? `|${rootViewNgh}` : '';
  const remainingNgh = isRootView ? componentViewNgh : rootNgh;
  let data = {};
  if (nghAttrValue !== '') {
    const transferState = injector.get(TransferState, null, {
      optional: true
    });
    if (transferState !== null) {
      const nghData = transferState.get(NGH_DATA_KEY, []);
      data = nghData[Number(nghAttrValue)];
      ngDevMode && assertDefined(data, 'Unable to retrieve hydration info from the TransferState.');
    }
  }
  const dehydratedView = {
    data,
    firstChild: rNode.firstChild ?? null
  };
  if (isRootView) {
    dehydratedView.firstChild = rNode;
    setSegmentHead(dehydratedView, 0, rNode.nextSibling);
  }
  if (remainingNgh) {
    rNode.setAttribute(NGH_ATTR_NAME, remainingNgh);
  } else {
    rNode.removeAttribute(NGH_ATTR_NAME);
  }
  ngDevMode && markRNodeAsClaimedByHydration(rNode, false);
  ngDevMode && ngDevMode.hydratedComponents++;
  return dehydratedView;
}
function enableRetrieveHydrationInfoImpl() {
  _retrieveHydrationInfoImpl = retrieveHydrationInfoImpl;
}
function retrieveHydrationInfo(rNode, injector, isRootView = false) {
  return _retrieveHydrationInfoImpl(rNode, injector, isRootView);
}
function getLNodeForHydration(viewRef) {
  let lView = viewRef._lView;
  const tView = lView[TVIEW$1];
  if (tView.type === 2) {
    return null;
  }
  if (isRootView(lView)) {
    lView = lView[HEADER_OFFSET];
  }
  return lView;
}
function getTextNodeContent(node) {
  return node.textContent?.replace(/\s/gm, '');
}
function processTextNodeMarkersBeforeHydration(node) {
  const doc = getDocument();
  const commentNodesIterator = doc.createNodeIterator(node, NodeFilter.SHOW_COMMENT, {
    acceptNode(node) {
      const content = getTextNodeContent(node);
      const isTextNodeMarker = content === "ngetn" || content === "ngtns";
      return isTextNodeMarker ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_REJECT;
    }
  });
  let currentNode;
  const nodes = [];
  while (currentNode = commentNodesIterator.nextNode()) {
    nodes.push(currentNode);
  }
  for (const node of nodes) {
    if (node.textContent === "ngetn") {
      node.replaceWith(doc.createTextNode(''));
    } else {
      node.remove();
    }
  }
}
var HydrationStatus;
(function (HydrationStatus) {
  HydrationStatus["Hydrated"] = "hydrated";
  HydrationStatus["Skipped"] = "skipped";
  HydrationStatus["Mismatched"] = "mismatched";
})(HydrationStatus || (HydrationStatus = {}));
const HYDRATION_INFO_KEY = '__ngDebugHydrationInfo__';
function patchHydrationInfo(node, info) {
  node[HYDRATION_INFO_KEY] = info;
}
function readHydrationInfo(node) {
  return node[HYDRATION_INFO_KEY] ?? null;
}
function markRNodeAsClaimedByHydration(node, checkIfAlreadyClaimed = true) {
  if (!ngDevMode) {
    throw new Error('Calling `markRNodeAsClaimedByHydration` in prod mode ' + 'is not supported and likely a mistake.');
  }
  if (checkIfAlreadyClaimed && isRNodeClaimedForHydration(node)) {
    throw new Error('Trying to claim a node, which was claimed already.');
  }
  patchHydrationInfo(node, {
    status: HydrationStatus.Hydrated
  });
  ngDevMode.hydratedNodes++;
}
function markRNodeAsSkippedByHydration(node) {
  if (!ngDevMode) {
    throw new Error('Calling `markRNodeAsSkippedByHydration` in prod mode ' + 'is not supported and likely a mistake.');
  }
  patchHydrationInfo(node, {
    status: HydrationStatus.Skipped
  });
  ngDevMode.componentsSkippedHydration++;
}
function countBlocksSkippedByHydration(injector) {
  const transferState = injector.get(TransferState);
  const nghDeferData = transferState.get(NGH_DEFER_BLOCKS_KEY, {});
  if (ngDevMode) {
    ngDevMode.deferBlocksWithIncrementalHydration = Object.keys(nghDeferData).length;
  }
}
function markRNodeAsHavingHydrationMismatch(node, expectedNodeDetails = null, actualNodeDetails = null) {
  if (!ngDevMode) {
    throw new Error('Calling `markRNodeAsMismatchedByHydration` in prod mode ' + 'is not supported and likely a mistake.');
  }
  while (node && !getComponent(node)) {
    node = node?.parentNode;
  }
  if (node) {
    patchHydrationInfo(node, {
      status: HydrationStatus.Mismatched,
      expectedNodeDetails,
      actualNodeDetails
    });
  }
}
function isRNodeClaimedForHydration(node) {
  return readHydrationInfo(node)?.status === HydrationStatus.Hydrated;
}
function setSegmentHead(hydrationInfo, index, node) {
  hydrationInfo.segmentHeads ??= {};
  hydrationInfo.segmentHeads[index] = node;
}
function getSegmentHead(hydrationInfo, index) {
  return hydrationInfo.segmentHeads?.[index] ?? null;
}
function isIncrementalHydrationEnabled(injector) {
  return injector.get(IS_INCREMENTAL_HYDRATION_ENABLED, false, {
    optional: true
  });
}
let incrementalHydrationEnabledWarned = false;
function resetIncrementalHydrationEnabledWarnedForTests() {
  incrementalHydrationEnabledWarned = false;
}
function warnIncrementalHydrationNotConfigured() {
  if (!incrementalHydrationEnabledWarned) {
    incrementalHydrationEnabledWarned = true;
    console.warn(formatRuntimeError(508, 'Angular has detected that some `@defer` blocks use `hydrate` triggers, ' + 'but incremental hydration was not enabled. Incremental hydration is enabled by default ' + 'with `provideClientHydration()`. Make sure `provideClientHydration()` is included in ' + 'your application config and that you have not opted out using `withNoIncrementalHydration()`.'));
  }
}
function assertSsrIdDefined(ssrUniqueId) {
  assertDefined(ssrUniqueId, 'Internal error: expecting an SSR id for a defer block that should be hydrated, but the id is not present');
}
function getNgContainerSize(hydrationInfo, index) {
  const data = hydrationInfo.data;
  let size = data[ELEMENT_CONTAINERS]?.[index] ?? null;
  if (size === null && data[CONTAINERS]?.[index]) {
    size = calcSerializedContainerSize(hydrationInfo, index);
  }
  return size;
}
function isSerializedElementContainer(hydrationInfo, index) {
  return hydrationInfo.data[ELEMENT_CONTAINERS]?.[index] !== undefined;
}
function getSerializedContainerViews(hydrationInfo, index) {
  return hydrationInfo.data[CONTAINERS]?.[index] ?? null;
}
function calcSerializedContainerSize(hydrationInfo, index) {
  const views = getSerializedContainerViews(hydrationInfo, index) ?? [];
  let numNodes = 0;
  for (let view of views) {
    numNodes += view[NUM_ROOT_NODES] * (view[MULTIPLIER] ?? 1);
  }
  return numNodes;
}
function initDisconnectedNodes(hydrationInfo) {
  if (typeof hydrationInfo.disconnectedNodes === 'undefined') {
    const nodeIds = hydrationInfo.data[DISCONNECTED_NODES];
    hydrationInfo.disconnectedNodes = nodeIds ? new Set(nodeIds) : null;
  }
  return hydrationInfo.disconnectedNodes;
}
function isDisconnectedNode$1(hydrationInfo, index) {
  if (typeof hydrationInfo.disconnectedNodes === 'undefined') {
    const nodeIds = hydrationInfo.data[DISCONNECTED_NODES];
    hydrationInfo.disconnectedNodes = nodeIds ? new Set(nodeIds) : null;
  }
  return !!initDisconnectedNodes(hydrationInfo)?.has(index);
}
function canHydrateNode(lView, tNode) {
  const hydrationInfo = lView[HYDRATION];
  return hydrationInfo !== null && !isInSkipHydrationBlock$1() && !isDetachedByI18n(tNode) && !isDisconnectedNode$1(hydrationInfo, tNode.index - HEADER_OFFSET);
}
function processTextNodeBeforeSerialization(context, node) {
  const el = node;
  const corruptedTextNodes = context.corruptedTextNodes;
  if (el.textContent === '') {
    corruptedTextNodes.set(el, "ngetn");
  } else if (el.nextSibling?.nodeType === Node.TEXT_NODE) {
    corruptedTextNodes.set(el, "ngtns");
  }
}
function convertHydrateTriggersToJsAction(triggers) {
  let actionList = [];
  if (triggers !== null) {
    if (triggers.has(4)) {
      actionList.push(...hoverEventNames);
    }
    if (triggers.has(3)) {
      actionList.push(...interactionEventNames);
    }
  }
  return actionList;
}
function getParentBlockHydrationQueue(deferBlockId, injector) {
  const dehydratedBlockRegistry = injector.get(DEHYDRATED_BLOCK_REGISTRY);
  const transferState = injector.get(TransferState);
  const deferBlockParents = transferState.get(NGH_DEFER_BLOCKS_KEY, {});
  let isTopMostDeferBlock = false;
  let currentBlockId = deferBlockId;
  let parentBlockPromise = null;
  const hydrationQueue = [];
  while (!isTopMostDeferBlock && currentBlockId) {
    ngDevMode && assertEqual(hydrationQueue.indexOf(currentBlockId), -1, 'Internal error: defer block hierarchy has a cycle.');
    isTopMostDeferBlock = dehydratedBlockRegistry.has(currentBlockId);
    const hydratingParentBlock = dehydratedBlockRegistry.hydrating.get(currentBlockId);
    if (parentBlockPromise === null && hydratingParentBlock != null) {
      parentBlockPromise = hydratingParentBlock.promise;
      break;
    }
    hydrationQueue.unshift(currentBlockId);
    currentBlockId = deferBlockParents[currentBlockId][DEFER_PARENT_BLOCK_ID];
  }
  return {
    parentBlockPromise,
    hydrationQueue
  };
}
function gatherDeferBlocksByJSActionAttribute(doc) {
  const jsactionNodes = doc.body.querySelectorAll('[jsaction]');
  const blockMap = new Set();
  const eventTypes = [hoverEventNames.join(':;'), interactionEventNames.join(':;')].join('|');
  for (let node of jsactionNodes) {
    const attr = node.getAttribute('jsaction');
    const blockId = node.getAttribute('ngb');
    if (attr?.match(eventTypes) && blockId !== null) {
      blockMap.add(node);
    }
  }
  return blockMap;
}
function appendDeferBlocksToJSActionMap(doc, injector) {
  const blockMap = gatherDeferBlocksByJSActionAttribute(doc);
  const jsActionMap = injector.get(JSACTION_BLOCK_ELEMENT_MAP);
  for (let rNode of blockMap) {
    sharedMapFunction(rNode, jsActionMap);
  }
}
let _retrieveDeferBlockDataImpl = () => {
  return {};
};
function retrieveDeferBlockDataImpl(injector) {
  const transferState = injector.get(TransferState, null, {
    optional: true
  });
  if (transferState !== null) {
    const nghDeferData = transferState.get(NGH_DEFER_BLOCKS_KEY, {});
    ngDevMode && assertDefined(nghDeferData, 'Unable to retrieve defer block info from the TransferState.');
    return nghDeferData;
  }
  return {};
}
function enableRetrieveDeferBlockDataImpl() {
  _retrieveDeferBlockDataImpl = retrieveDeferBlockDataImpl;
}
function retrieveDeferBlockData(injector) {
  return _retrieveDeferBlockDataImpl(injector);
}
function isTimerTrigger(triggerInfo) {
  return typeof triggerInfo === 'object' && triggerInfo.trigger === 5;
}
function getHydrateTimerTrigger(blockData) {
  const trigger = blockData[DEFER_HYDRATE_TRIGGERS]?.find(t => isTimerTrigger(t));
  return trigger?.delay ?? null;
}
function getHydrateViewportTrigger(blockData) {
  const details = blockData[DEFER_HYDRATE_TRIGGERS];
  if (details) {
    for (const current of details) {
      if (current === 2) {
        return true;
      } else if (typeof current === 'object' && current.trigger === 2) {
        return current.intersectionObserverOptions || true;
      }
    }
  }
  return null;
}
function hasHydrateTrigger(blockData, trigger) {
  return blockData[DEFER_HYDRATE_TRIGGERS]?.includes(trigger) ?? false;
}
function createBlockSummary(blockInfo) {
  return {
    data: blockInfo,
    hydrate: {
      idle: hasHydrateTrigger(blockInfo, 0),
      immediate: hasHydrateTrigger(blockInfo, 1),
      timer: getHydrateTimerTrigger(blockInfo),
      viewport: getHydrateViewportTrigger(blockInfo)
    }
  };
}
function processBlockData(injector) {
  const blockData = retrieveDeferBlockData(injector);
  let blockDetails = new Map();
  for (let blockId in blockData) {
    blockDetails.set(blockId, createBlockSummary(blockData[blockId]));
  }
  return blockDetails;
}
function isSsrContentsIntegrity(node) {
  return !!node && node.nodeType === Node.COMMENT_NODE && node.textContent?.trim() === SSR_CONTENT_INTEGRITY_MARKER;
}
function skipTextNodes(node) {
  while (node && node.nodeType === Node.TEXT_NODE) {
    node = node.previousSibling;
  }
  return node;
}
function verifySsrContentsIntegrity(doc) {
  for (const node of doc.body.childNodes) {
    if (isSsrContentsIntegrity(node)) {
      return;
    }
  }
  const beforeBody = skipTextNodes(doc.body.previousSibling);
  if (isSsrContentsIntegrity(beforeBody)) {
    return;
  }
  let endOfHead = skipTextNodes(doc.head.lastChild);
  if (isSsrContentsIntegrity(endOfHead)) {
    return;
  }
  throw new RuntimeError(-507, typeof ngDevMode !== 'undefined' && ngDevMode && 'Angular hydration logic detected that HTML content of this page was modified after it ' + 'was produced during server side rendering. Make sure that there are no optimizations ' + 'that remove comment nodes from HTML enabled on your CDN. Angular hydration ' + 'relies on HTML produced by the server, including whitespaces and comment nodes.');
}

function refreshContentQueries(tView, lView) {
  const contentQueries = tView.contentQueries;
  if (contentQueries !== null) {
    const prevConsumer = setActiveConsumer(null);
    try {
      for (let i = 0; i < contentQueries.length; i += 2) {
        const queryStartIdx = contentQueries[i];
        const directiveDefIdx = contentQueries[i + 1];
        if (directiveDefIdx !== -1) {
          const directiveDef = tView.data[directiveDefIdx];
          ngDevMode && assertDefined(directiveDef, 'DirectiveDef not found.');
          ngDevMode && assertDefined(directiveDef.contentQueries, 'contentQueries function should be defined');
          setCurrentQueryIndex(queryStartIdx);
          directiveDef.contentQueries(2, lView[directiveDefIdx], directiveDefIdx);
        }
      }
    } finally {
      setActiveConsumer(prevConsumer);
    }
  }
}
function executeViewQueryFn(flags, viewQueryFn, component) {
  ngDevMode && assertDefined(viewQueryFn, 'View queries function to execute must be defined.');
  setCurrentQueryIndex(0);
  const prevConsumer = setActiveConsumer(null);
  try {
    viewQueryFn(flags, component);
  } finally {
    setActiveConsumer(prevConsumer);
  }
}
function executeContentQueries(tView, tNode, lView) {
  if (isContentQueryHost(tNode)) {
    const prevConsumer = setActiveConsumer(null);
    try {
      const start = tNode.directiveStart;
      const end = tNode.directiveEnd;
      for (let directiveIndex = start; directiveIndex < end; directiveIndex++) {
        const def = tView.data[directiveIndex];
        if (def.contentQueries) {
          const directiveInstance = lView[directiveIndex];
          ngDevMode && assertDefined(directiveIndex, 'Incorrect reference to a directive defining a content query');
          def.contentQueries(1, directiveInstance, directiveIndex);
        }
      }
    } finally {
      setActiveConsumer(prevConsumer);
    }
  }
}

var ViewEncapsulation;
(function (ViewEncapsulation) {
  ViewEncapsulation[ViewEncapsulation["Emulated"] = 0] = "Emulated";
  ViewEncapsulation[ViewEncapsulation["None"] = 2] = "None";
  ViewEncapsulation[ViewEncapsulation["ShadowDom"] = 3] = "ShadowDom";
  ViewEncapsulation[ViewEncapsulation["ExperimentalIsolatedShadowDom"] = 4] = "ExperimentalIsolatedShadowDom";
})(ViewEncapsulation || (ViewEncapsulation = {}));

class SafeValueImpl {
  changingThisBreaksApplicationSecurity;
  constructor(changingThisBreaksApplicationSecurity) {
    this.changingThisBreaksApplicationSecurity = changingThisBreaksApplicationSecurity;
  }
  toString() {
    return `SafeValue must use [property]=binding: ${this.changingThisBreaksApplicationSecurity}` + (ngDevMode ? ` (see ${XSS_SECURITY_URL})` : '');
  }
}
class SafeHtmlImpl extends SafeValueImpl {
  getTypeName() {
    return "HTML";
  }
}
class SafeStyleImpl extends SafeValueImpl {
  getTypeName() {
    return "Style";
  }
}
class SafeScriptImpl extends SafeValueImpl {
  getTypeName() {
    return "Script";
  }
}
class SafeUrlImpl extends SafeValueImpl {
  getTypeName() {
    return "URL";
  }
}
class SafeResourceUrlImpl extends SafeValueImpl {
  getTypeName() {
    return "ResourceURL";
  }
}
function unwrapSafeValue(value) {
  return value instanceof SafeValueImpl ? value.changingThisBreaksApplicationSecurity : value;
}
function allowSanitizationBypassAndThrow(value, type) {
  const actualType = getSanitizationBypassType(value);
  if (actualType != null && actualType !== type) {
    if (actualType === "ResourceURL" && type === "URL") return true;
    throw new Error(`Required a safe ${type}, got a ${actualType} (see ${XSS_SECURITY_URL})`);
  }
  return actualType === type;
}
function getSanitizationBypassType(value) {
  return value instanceof SafeValueImpl && value.getTypeName() || null;
}
function bypassSanitizationTrustHtml(trustedHtml) {
  return new SafeHtmlImpl(trustedHtml);
}
function bypassSanitizationTrustStyle(trustedStyle) {
  return new SafeStyleImpl(trustedStyle);
}
function bypassSanitizationTrustScript(trustedScript) {
  return new SafeScriptImpl(trustedScript);
}
function bypassSanitizationTrustUrl(trustedUrl) {
  return new SafeUrlImpl(trustedUrl);
}
function bypassSanitizationTrustResourceUrl(trustedResourceUrl) {
  return new SafeResourceUrlImpl(trustedResourceUrl);
}

const CUSTOM_ELEMENTS_SCHEMA = {
  name: 'custom-elements'
};
const NO_ERRORS_SCHEMA = {
  name: 'no-errors-schema'
};

let shouldThrowErrorOnUnknownElement = false;
function ɵsetUnknownElementStrictMode(shouldThrow) {
  shouldThrowErrorOnUnknownElement = shouldThrow;
}
function ɵgetUnknownElementStrictMode() {
  return shouldThrowErrorOnUnknownElement;
}
let shouldThrowErrorOnUnknownProperty = false;
function ɵsetUnknownPropertyStrictMode(shouldThrow) {
  shouldThrowErrorOnUnknownProperty = shouldThrow;
}
function ɵgetUnknownPropertyStrictMode() {
  return shouldThrowErrorOnUnknownProperty;
}
function validateElementIsKnown(lView, tNode) {
  const tView = lView[TVIEW$1];
  if (tView.schemas === null) return;
  const tagName = tNode.value;
  if (!isDirectiveHost(tNode) && tagName !== null) {
    const isUnknown = typeof HTMLUnknownElement !== 'undefined' && HTMLUnknownElement && getNativeByTNode(tNode, lView) instanceof HTMLUnknownElement || typeof customElements !== 'undefined' && tagName.indexOf('-') > -1 && !customElements.get(tagName);
    if (isUnknown && !matchingSchemas(tView.schemas, tagName)) {
      const isHostStandalone = isHostComponentStandalone(lView);
      const templateLocation = getTemplateLocationDetails(lView);
      const schemas = `'${isHostStandalone ? '@Component' : '@NgModule'}.schemas'`;
      let message = `'${tagName}' is not a known element${templateLocation}:\n`;
      message += `1. If '${tagName}' is an Angular component, then verify that it is ${isHostStandalone ? "included in the '@Component.imports' of this component" : 'a part of an @NgModule where this component is declared'}.\n`;
      if (tagName && tagName.indexOf('-') > -1) {
        message += `2. If '${tagName}' is a Web Component then add 'CUSTOM_ELEMENTS_SCHEMA' to the ${schemas} of this component to suppress this message.`;
      } else {
        message += `2. To allow any element add 'NO_ERRORS_SCHEMA' to the ${schemas} of this component.`;
      }
      if (shouldThrowErrorOnUnknownElement) {
        throw new RuntimeError(304, message);
      } else {
        console.error(formatRuntimeError(304, message));
      }
    }
  }
}
function isPropertyValid(element, propName, tagName, schemas) {
  if (schemas === null) return true;
  if (matchingSchemas(schemas, tagName) || propName in element || isAnimationProp(propName)) {
    return true;
  }
  return typeof Node === 'undefined' || Node === null || !(element instanceof Node);
}
function handleUnknownPropertyError(propName, tagName, nodeType, lView) {
  if (!tagName && nodeType === 4) {
    tagName = 'ng-template';
  }
  const isHostStandalone = isHostComponentStandalone(lView);
  const templateLocation = getTemplateLocationDetails(lView);
  let message = `Can't bind to '${propName}' since it isn't a known property of '${tagName}'${templateLocation}.`;
  const schemas = `'${isHostStandalone ? '@Component' : '@NgModule'}.schemas'`;
  const importLocation = isHostStandalone ? "included in the '@Component.imports' of this component" : 'a part of an @NgModule where this component is declared';
  if (KNOWN_CONTROL_FLOW_DIRECTIVES.has(propName)) {
    const correspondingImport = KNOWN_CONTROL_FLOW_DIRECTIVES.get(propName);
    message += `\nIf the '${propName}' is an Angular control flow directive, ` + `please make sure that either the '${correspondingImport}' directive or the 'CommonModule' is ${importLocation}.`;
  } else {
    message += `\n1. If '${tagName}' is an Angular component and it has the ` + `'${propName}' input, then verify that it is ${importLocation}.`;
    if (tagName && tagName.indexOf('-') > -1) {
      message += `\n2. If '${tagName}' is a Web Component then add 'CUSTOM_ELEMENTS_SCHEMA' ` + `to the ${schemas} of this component to suppress this message.`;
      message += `\n3. To allow any property add 'NO_ERRORS_SCHEMA' to ` + `the ${schemas} of this component.`;
    } else {
      message += `\n2. To allow any property add 'NO_ERRORS_SCHEMA' to ` + `the ${schemas} of this component.`;
    }
  }
  reportUnknownPropertyError(message);
}
function reportUnknownPropertyError(message) {
  if (shouldThrowErrorOnUnknownProperty) {
    throw new RuntimeError(303, message);
  } else {
    console.error(formatRuntimeError(303, message));
  }
}
function getDeclarationComponentDef(lView) {
  !ngDevMode && throwError('Must never be called in production mode');
  const declarationLView = lView[DECLARATION_COMPONENT_VIEW];
  const context = declarationLView[CONTEXT];
  if (!context) return null;
  return context.constructor ? getComponentDef(context.constructor) : null;
}
function isHostComponentStandalone(lView) {
  !ngDevMode && throwError('Must never be called in production mode');
  const componentDef = getDeclarationComponentDef(lView);
  return !!componentDef?.standalone;
}
function getTemplateLocationDetails(lView) {
  !ngDevMode && throwError('Must never be called in production mode');
  const hostComponentDef = getDeclarationComponentDef(lView);
  const componentClassName = hostComponentDef?.type?.name;
  return componentClassName ? ` (used in the '${componentClassName}' component template)` : '';
}
const KNOWN_CONTROL_FLOW_DIRECTIVES = new Map([['ngIf', 'NgIf'], ['ngFor', 'NgFor'], ['ngSwitchCase', 'NgSwitchCase'], ['ngSwitchDefault', 'NgSwitchDefault']]);
function matchingSchemas(schemas, tagName) {
  if (schemas !== null) {
    for (let i = 0; i < schemas.length; i++) {
      const schema = schemas[i];
      if (schema === NO_ERRORS_SCHEMA || schema === CUSTOM_ELEMENTS_SCHEMA && tagName && tagName.indexOf('-') > -1) {
        return true;
      }
    }
  }
  return false;
}

const NAMESPACE_URIS = {
  'http://www.w3.org/2000/svg': SVG_NAMESPACE,
  'http://www.w3.org/1998/Math/MathML': MATH_ML_NAMESPACE
};

let policy$1;
function getPolicy$1() {
  if (policy$1 === undefined) {
    policy$1 = null;
    if (_global.trustedTypes) {
      try {
        policy$1 = _global.trustedTypes.createPolicy('angular', {
          createHTML: s => s,
          createScript: s => s,
          createScriptURL: s => s
        });
      } catch {}
    }
  }
  return policy$1;
}
function trustedHTMLFromString(html) {
  return getPolicy$1()?.createHTML(html) || html;
}
function trustedScriptURLFromString(url) {
  return getPolicy$1()?.createScriptURL(url) || url;
}

let policy;
function getPolicy() {
  if (policy === undefined) {
    policy = null;
    if (_global.trustedTypes) {
      try {
        policy = _global.trustedTypes.createPolicy('angular#unsafe-bypass', {
          createHTML: s => s,
          createScript: s => s,
          createScriptURL: s => s
        });
      } catch {}
    }
  }
  return policy;
}
function trustedHTMLFromStringBypass(html) {
  return getPolicy()?.createHTML(html) || html;
}
function trustedScriptFromStringBypass(script) {
  return getPolicy()?.createScript(script) || script;
}
function trustedScriptURLFromStringBypass(url) {
  return getPolicy()?.createScriptURL(url) || url;
}

function getInertBodyHelper(defaultDoc) {
  const inertDocumentHelper = new InertDocumentHelper(defaultDoc);
  return isDOMParserAvailable() ? new DOMParserHelper(inertDocumentHelper) : inertDocumentHelper;
}
class DOMParserHelper {
  inertDocumentHelper;
  constructor(inertDocumentHelper) {
    this.inertDocumentHelper = inertDocumentHelper;
  }
  getInertBodyElement(html) {
    html = '<body><remove></remove>' + html;
    try {
      const body = new window.DOMParser().parseFromString(trustedHTMLFromString(html), 'text/html').body;
      if (body === null) {
        return this.inertDocumentHelper.getInertBodyElement(html);
      }
      body.firstChild?.remove();
      return body;
    } catch {
      return null;
    }
  }
}
class InertDocumentHelper {
  defaultDoc;
  inertDocument;
  constructor(defaultDoc) {
    this.defaultDoc = defaultDoc;
    this.inertDocument = this.defaultDoc.implementation.createHTMLDocument('sanitization-inert');
  }
  getInertBodyElement(html) {
    const templateEl = this.inertDocument.createElement('template');
    templateEl.innerHTML = trustedHTMLFromString(html);
    return templateEl;
  }
}
function isDOMParserAvailable() {
  try {
    return !!new window.DOMParser().parseFromString(trustedHTMLFromString(''), 'text/html');
  } catch {
    return false;
  }
}

const SAFE_URL_PATTERN = /^(?!javascript:)(?:[a-z0-9+.-]+:|[^&:\/?#]*(?:[\/?#]|$))/i;
function _sanitizeUrl(url) {
  url = String(url);
  if (url.match(SAFE_URL_PATTERN)) return url;
  if (typeof ngDevMode === 'undefined' || ngDevMode) {
    console.warn(`WARNING: sanitizing unsafe URL value ${url} (see ${XSS_SECURITY_URL})`);
  }
  return 'unsafe:' + url;
}

function tagSet(tags) {
  const res = Object.create(null);
  for (const t of tags.split(',')) res[t] = true;
  return res;
}
function merge(...sets) {
  const res = Object.create(null);
  for (const s of sets) {
    for (const v in s) {
      if (Object.hasOwn(s, v)) res[v] = true;
    }
  }
  return res;
}
const VOID_ELEMENTS = tagSet('area,br,col,hr,img,wbr');
const OPTIONAL_END_TAG_BLOCK_ELEMENTS = tagSet('colgroup,dd,dt,li,p,tbody,td,tfoot,th,thead,tr');
const OPTIONAL_END_TAG_INLINE_ELEMENTS = tagSet('rp,rt');
const OPTIONAL_END_TAG_ELEMENTS = merge(OPTIONAL_END_TAG_INLINE_ELEMENTS, OPTIONAL_END_TAG_BLOCK_ELEMENTS);
const BLOCK_ELEMENTS = merge(OPTIONAL_END_TAG_BLOCK_ELEMENTS, tagSet('address,article,' + 'aside,blockquote,caption,center,del,details,dialog,dir,div,dl,figure,figcaption,footer,h1,h2,h3,h4,h5,' + 'h6,header,hgroup,hr,ins,main,map,menu,nav,ol,pre,section,summary,table,ul'));
const INLINE_ELEMENTS = merge(OPTIONAL_END_TAG_INLINE_ELEMENTS, tagSet('a,abbr,acronym,audio,b,' + 'bdi,bdo,big,br,cite,code,del,dfn,em,font,i,img,ins,kbd,label,map,mark,picture,q,ruby,rp,rt,s,' + 'samp,small,source,span,strike,strong,sub,sup,time,track,tt,u,var,video'));
const VALID_ELEMENTS = merge(VOID_ELEMENTS, BLOCK_ELEMENTS, INLINE_ELEMENTS, OPTIONAL_END_TAG_ELEMENTS);
const URI_ATTRS = tagSet('background,cite,href,itemtype,longdesc,poster,src,xlink:href');
const HTML_ATTRS = tagSet('abbr,accesskey,align,alt,autoplay,axis,bgcolor,border,cellpadding,cellspacing,class,clear,color,cols,colspan,' + 'compact,controls,coords,datetime,default,dir,download,face,headers,height,hidden,hreflang,hspace,' + 'ismap,itemscope,itemprop,kind,label,lang,language,loop,media,muted,nohref,nowrap,open,preload,rel,rev,role,rows,rowspan,rules,' + 'scope,scrolling,shape,size,sizes,span,srclang,srcset,start,summary,tabindex,target,title,translate,type,usemap,' + 'valign,value,vspace,width');
const ARIA_ATTRS = tagSet('aria-activedescendant,aria-atomic,aria-autocomplete,aria-busy,aria-checked,aria-colcount,aria-colindex,' + 'aria-colspan,aria-controls,aria-current,aria-describedby,aria-details,aria-disabled,aria-dropeffect,' + 'aria-errormessage,aria-expanded,aria-flowto,aria-grabbed,aria-haspopup,aria-hidden,aria-invalid,' + 'aria-keyshortcuts,aria-label,aria-labelledby,aria-level,aria-live,aria-modal,aria-multiline,' + 'aria-multiselectable,aria-orientation,aria-owns,aria-placeholder,aria-posinset,aria-pressed,aria-readonly,' + 'aria-relevant,aria-required,aria-roledescription,aria-rowcount,aria-rowindex,aria-rowspan,aria-selected,' + 'aria-setsize,aria-sort,aria-valuemax,aria-valuemin,aria-valuenow,aria-valuetext');
const VALID_ATTRS = merge(URI_ATTRS, HTML_ATTRS, ARIA_ATTRS);
const SKIP_TRAVERSING_CONTENT_IF_INVALID_ELEMENTS = tagSet('script,style,template');
class SanitizingHtmlSerializer {
  sanitizedSomething = false;
  buf = [];
  sanitizeChildren(el) {
    let current = el.firstChild;
    let traverseContent = true;
    let parentNodes = [];
    while (current) {
      if (current.nodeType === Node.ELEMENT_NODE) {
        traverseContent = this.startElement(current);
      } else if (current.nodeType === Node.TEXT_NODE) {
        this.chars(current.nodeValue);
      } else {
        this.sanitizedSomething = true;
      }
      if (traverseContent && current.firstChild) {
        parentNodes.push(current);
        current = getFirstChild(current);
        continue;
      }
      while (current) {
        if (current.nodeType === Node.ELEMENT_NODE) {
          this.endElement(current);
        }
        let next = getNextSibling(current);
        if (next) {
          current = next;
          break;
        }
        current = parentNodes.pop();
      }
    }
    return this.buf.join('');
  }
  startElement(element) {
    const tagName = getNodeName(element).toLowerCase();
    if (!Object.hasOwn(VALID_ELEMENTS, tagName)) {
      this.sanitizedSomething = true;
      return !Object.hasOwn(SKIP_TRAVERSING_CONTENT_IF_INVALID_ELEMENTS, tagName);
    }
    this.buf.push('<');
    this.buf.push(tagName);
    const elAttrs = element.attributes;
    for (let i = 0; i < elAttrs.length; i++) {
      const elAttr = elAttrs.item(i);
      const attrName = elAttr.name;
      const lower = attrName.toLowerCase();
      if (!Object.hasOwn(VALID_ATTRS, lower)) {
        this.sanitizedSomething = true;
        continue;
      }
      let value = elAttr.value;
      if (URI_ATTRS[lower]) value = _sanitizeUrl(value);
      this.buf.push(' ', attrName, '="', encodeEntities(value), '"');
    }
    this.buf.push('>');
    return true;
  }
  endElement(current) {
    const tagName = getNodeName(current).toLowerCase();
    if (Object.hasOwn(VALID_ELEMENTS, tagName) && !Object.hasOwn(VOID_ELEMENTS, tagName)) {
      this.buf.push('</');
      this.buf.push(tagName);
      this.buf.push('>');
    }
  }
  chars(chars) {
    this.buf.push(encodeEntities(chars));
  }
}
function isClobberedElement(parentNode, childNode) {
  return (parentNode.compareDocumentPosition(childNode) & Node.DOCUMENT_POSITION_CONTAINED_BY) !== Node.DOCUMENT_POSITION_CONTAINED_BY;
}
function getNextSibling(node) {
  const nextSibling = node.nextSibling;
  if (nextSibling && node !== nextSibling.previousSibling) {
    throw clobberedElementError(nextSibling);
  }
  return nextSibling;
}
function getFirstChild(node) {
  const firstChild = node.firstChild;
  if (firstChild && isClobberedElement(node, firstChild)) {
    throw clobberedElementError(firstChild);
  }
  return firstChild;
}
function getNodeName(node) {
  const nodeName = node.nodeName;
  return typeof nodeName === 'string' ? nodeName : 'FORM';
}
function clobberedElementError(node) {
  return new Error(`Failed to sanitize html because the element is clobbered: ${node.outerHTML}`);
}
const SURROGATE_PAIR_REGEXP = /[\uD800-\uDBFF][\uDC00-\uDFFF]/g;
const NON_ALPHANUMERIC_REGEXP = /([^\#-~ |!])/g;
function encodeEntities(value) {
  return value.replace(/&/g, '&amp;').replace(SURROGATE_PAIR_REGEXP, function (match) {
    const hi = match.charCodeAt(0);
    const low = match.charCodeAt(1);
    return '&#' + ((hi - 0xd800) * 0x400 + (low - 0xdc00) + 0x10000) + ';';
  }).replace(NON_ALPHANUMERIC_REGEXP, function (match) {
    return '&#' + match.charCodeAt(0) + ';';
  }).replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
let inertBodyHelper;
function _sanitizeHtml(defaultDoc, unsafeHtmlInput) {
  let inertBodyElement = null;
  try {
    inertBodyHelper = inertBodyHelper || getInertBodyHelper(defaultDoc);
    let unsafeHtml = unsafeHtmlInput ? String(unsafeHtmlInput) : '';
    inertBodyElement = inertBodyHelper.getInertBodyElement(unsafeHtml);
    let mXSSAttempts = 5;
    let parsedHtml = unsafeHtml;
    do {
      if (mXSSAttempts === 0) {
        throw new Error('Failed to sanitize html because the input is unstable');
      }
      mXSSAttempts--;
      unsafeHtml = parsedHtml;
      parsedHtml = inertBodyElement.innerHTML;
      inertBodyElement = inertBodyHelper.getInertBodyElement(unsafeHtml);
    } while (unsafeHtml !== parsedHtml);
    const sanitizer = new SanitizingHtmlSerializer();
    const safeHtml = sanitizer.sanitizeChildren(getTemplateContent(inertBodyElement) || inertBodyElement);
    if ((typeof ngDevMode === 'undefined' || ngDevMode) && sanitizer.sanitizedSomething) {
      console.warn(`WARNING: sanitizing HTML stripped some content, see ${XSS_SECURITY_URL}`);
    }
    return trustedHTMLFromString(safeHtml);
  } finally {
    if (inertBodyElement) {
      const parent = getTemplateContent(inertBodyElement) || inertBodyElement;
      while (parent.firstChild) {
        parent.firstChild.remove();
      }
    }
  }
}
function getTemplateContent(el) {
  return 'content' in el && isTemplateElement(el) ? el.content : null;
}
function isTemplateElement(el) {
  return el.nodeType === Node.ELEMENT_NODE && el.nodeName === 'TEMPLATE';
}

const COMMENT_DISALLOWED = /^>|^->|<!--|-->|--!>|<!-$/g;
const COMMENT_DELIMITER = /(<|>)/g;
const COMMENT_DELIMITER_ESCAPED = '\u200B$1\u200B';
function escapeCommentText(value) {
  return value.replace(COMMENT_DISALLOWED, text => text.replace(COMMENT_DELIMITER, COMMENT_DELIMITER_ESCAPED));
}

function createTextNode(renderer, value) {
  return renderer.createText(value);
}
function updateTextNode(renderer, rNode, value) {
  renderer.setValue(rNode, value);
}
function createCommentNode(renderer, value) {
  return renderer.createComment(escapeCommentText(value));
}
function createElementNode(renderer, name, namespace) {
  return renderer.createElement(name, namespace);
}
function nativeInsertBefore(renderer, parent, child, beforeNode, isMove) {
  renderer.insertBefore(parent, child, beforeNode, isMove);
}
function nativeAppendChild(renderer, parent, child) {
  ngDevMode && assertDefined(parent, 'parent node must be defined');
  renderer.appendChild(parent, child);
}
function nativeAppendOrInsertBefore(renderer, parent, child, beforeNode, isMove) {
  if (beforeNode !== null) {
    nativeInsertBefore(renderer, parent, child, beforeNode, isMove);
  } else {
    nativeAppendChild(renderer, parent, child);
  }
}
function nativeRemoveNode(renderer, rNode, isHostElement, requireSynchronousElementRemoval) {
  renderer.removeChild(null, rNode, isHostElement, requireSynchronousElementRemoval);
}
function clearElementContents(rElement) {
  rElement.textContent = '';
}
function writeDirectStyle(renderer, element, newValue) {
  ngDevMode && assertString(newValue, "'newValue' should be a string");
  renderer.setAttribute(element, 'style', newValue);
}
function writeDirectClass(renderer, element, newValue) {
  ngDevMode && assertString(newValue, "'newValue' should be a string");
  if (newValue === '') {
    renderer.removeAttribute(element, 'class');
  } else {
    renderer.setAttribute(element, 'class', newValue);
  }
}
function setupStaticAttributes(renderer, element, tNode) {
  const {
    mergedAttrs,
    classes,
    styles
  } = tNode;
  if (mergedAttrs !== null) {
    setUpAttributes(renderer, element, mergedAttrs);
  }
  if (classes !== null) {
    writeDirectClass(renderer, element, classes);
  }
  if (styles !== null) {
    writeDirectStyle(renderer, element, styles);
  }
}

function enforceIframeSecurity(iframe) {
  const lView = getLView();
  iframe.src = '';
  iframe.srcdoc = trustedHTMLFromString('');
  nativeRemoveNode(lView[RENDERER], iframe);
}

function splitNsName(elementName, fatal = true) {
  if (elementName[0] != ':') {
    return [null, elementName];
  }
  const colonIndex = elementName.indexOf(':', 1);
  if (colonIndex === -1) {
    if (fatal) {
      throw new Error(`Unsupported format "${elementName}" expecting ":namespace:name"`);
    } else {
      return [null, elementName];
    }
  }
  return [elementName.slice(1, colonIndex), elementName.slice(colonIndex + 1)];
}

function ɵɵsanitizeHtml(unsafeHtml, tagName, propName) {
  if (tagName !== undefined && propName !== undefined && getSecurityContext(tagName, propName) !== SecurityContext.HTML) {
    return unsafeHtml;
  }
  const sanitizer = getSanitizer();
  if (sanitizer) {
    return trustedHTMLFromStringBypass(sanitizer.sanitize(SecurityContext.HTML, unsafeHtml) || '');
  }
  if (allowSanitizationBypassAndThrow(unsafeHtml, "HTML")) {
    return trustedHTMLFromStringBypass(unwrapSafeValue(unsafeHtml));
  }
  return _sanitizeHtml(getDocument(), renderStringify(unsafeHtml));
}
function ɵɵsanitizeStyle(unsafeStyle) {
  const sanitizer = getSanitizer();
  if (sanitizer) {
    return sanitizer.sanitize(SecurityContext.STYLE, unsafeStyle) || '';
  }
  if (allowSanitizationBypassAndThrow(unsafeStyle, "Style")) {
    return unwrapSafeValue(unsafeStyle);
  }
  return renderStringify(unsafeStyle);
}
function ɵɵsanitizeUrl(unsafeUrl) {
  const sanitizer = getSanitizer();
  if (sanitizer) {
    return sanitizer.sanitize(SecurityContext.URL, unsafeUrl) || '';
  }
  if (allowSanitizationBypassAndThrow(unsafeUrl, "URL")) {
    return unwrapSafeValue(unsafeUrl);
  }
  return _sanitizeUrl(renderStringify(unsafeUrl));
}
function ɵɵsanitizeResourceUrl(unsafeResourceUrl) {
  const sanitizer = getSanitizer();
  if (sanitizer) {
    return trustedScriptURLFromStringBypass(sanitizer.sanitize(SecurityContext.RESOURCE_URL, unsafeResourceUrl) || '');
  }
  if (allowSanitizationBypassAndThrow(unsafeResourceUrl, "ResourceURL")) {
    return trustedScriptURLFromStringBypass(unwrapSafeValue(unsafeResourceUrl));
  }
  throw new RuntimeError(-904, ngDevMode && `unsafe value used in a resource URL context (see ${XSS_SECURITY_URL})`);
}
function ɵɵsanitizeScript(unsafeScript) {
  const sanitizer = getSanitizer();
  if (sanitizer) {
    return trustedScriptFromStringBypass(sanitizer.sanitize(SecurityContext.SCRIPT, unsafeScript) || '');
  }
  if (allowSanitizationBypassAndThrow(unsafeScript, "Script")) {
    return trustedScriptFromStringBypass(unwrapSafeValue(unsafeScript));
  }
  throw new RuntimeError(905, ngDevMode && 'unsafe value used in a script context');
}
function ɵɵtrustConstantHtml(html) {
  if (ngDevMode && (!Array.isArray(html) || !Array.isArray(html.raw) || html.length !== 1)) {
    throw new Error(`Unexpected interpolation in trusted HTML constant: ${html.join('?')}`);
  }
  return trustedHTMLFromString(html[0]);
}
function ɵɵtrustConstantResourceUrl(url) {
  if (ngDevMode && (!Array.isArray(url) || !Array.isArray(url.raw) || url.length !== 1)) {
    throw new Error(`Unexpected interpolation in trusted URL constant: ${url.join('?')}`);
  }
  return trustedScriptURLFromString(url[0]);
}
function getUrlSanitizer(tag, prop) {
  switch (getSecurityContext(tag, prop)) {
    case SecurityContext.RESOURCE_URL:
      return ɵɵsanitizeResourceUrl;
    case SecurityContext.URL:
      return ɵɵsanitizeUrl;
    default:
      return null;
  }
}
function ɵɵsanitizeUrlOrResourceUrl(unsafeUrl, tag, prop) {
  return getUrlSanitizer(tag, prop)?.(unsafeUrl) ?? unsafeUrl;
}
function validateAgainstEventProperties(name) {
  if (name.toLowerCase().startsWith('on')) {
    const errorMessage = `Binding to event property '${name}' is disallowed for security reasons, ` + `please use (${name.slice(2)})=...` + `\nIf '${name}' is a directive input, make sure the directive is imported by the` + ` current module.`;
    throw new RuntimeError(306, errorMessage);
  }
}
function getSanitizer() {
  const lView = getLView();
  return lView && lView[ENVIRONMENT].sanitizer;
}
function getSecurityContext(tagName, propName) {
  const [namespace, resolvedTagName] = resolveElement(tagName);
  return checkSecurityContext(resolvedTagName, propName, namespace);
}
function resolveElement(tagName) {
  tagName = tagName.toLowerCase();
  const splitResult = splitNsName(tagName, false);
  if (splitResult[0]) {
    return splitResult;
  }
  const index = getSelectedIndex();
  const tNode = index === -1 ? null : getSelectedTNode();
  let namespace = tNode?.namespace;
  if (tagName === "#host" && tNode?.type === 2) {
    const element = getNativeByTNode(tNode, getLView());
    if (element.tagName) {
      tagName = element.tagName.toLowerCase();
    }
    if (namespace == null) {
      const namespaceURI = element.namespaceURI;
      namespace = namespaceURI && NAMESPACE_URIS[namespaceURI];
    }
  }
  return [namespace, tagName];
}
const SECURITY_SENSITIVE_ATTRIBUTE_NAMES = new Set(['href', 'xlink:href']);
const SVG_ANIMATION_SENSITIVE_STATIC_VALUES = {
  'animate': {
    'to': SECURITY_SENSITIVE_ATTRIBUTE_NAMES,
    'values': SECURITY_SENSITIVE_ATTRIBUTE_NAMES,
    'from': SECURITY_SENSITIVE_ATTRIBUTE_NAMES
  },
  'set': {
    'to': SECURITY_SENSITIVE_ATTRIBUTE_NAMES
  }
};
function ɵɵvalidateAttribute(value, tagName, attributeName) {
  const index = getSelectedIndex();
  const tNode = index === -1 ? null : getSelectedTNode();
  if (tNode && tNode.type !== 2) {
    return value;
  }
  const [namespace, resolvedTagName] = resolveElement(tagName);
  const securityContext = checkSecurityContext(resolvedTagName, attributeName, namespace);
  if (securityContext !== SecurityContext.ATTRIBUTE_NO_BINDING) {
    return value;
  }
  const lView = getLView();
  if (tNode) {
    if (resolvedTagName === 'iframe') {
      const element = getNativeByTNode(tNode, lView);
      enforceIframeSecurity(element);
    } else if (namespace === SVG_NAMESPACE || !namespace) {
      const config = SVG_ANIMATION_SENSITIVE_STATIC_VALUES[resolvedTagName]?.[attributeName.toLowerCase()];
      if (config) {
        const element = getNativeByTNode(tNode, lView);
        const attributeNameValue = getSecuritySensitiveSVGAnimationAttributeName(element, config);
        if (attributeNameValue) {
          const errorMessage = ngDevMode && `Angular has detected that the \`${attributeName}\` was applied ` + `as a binding to the <${resolvedTagName}> element${getTemplateLocationDetails(lView)}. ` + `For security reasons, the \`${attributeName}\` can be set on the <${resolvedTagName}> element ` + `as a static attribute only when the "attributeName" is set to \'${attributeNameValue}\'. \n` + `To fix this, switch the \`${attributeNameValue}\` binding to a static attribute ` + `in a template or in host bindings section.`;
          throw new RuntimeError(-910, errorMessage);
        }
        return value;
      }
    }
  }
  const errorMessage = ngDevMode && `Angular has detected that the \`${attributeName}\` was applied ` + `as a binding to the <${resolvedTagName}> element${tNode ? getTemplateLocationDetails(lView) : ''}. ` + `For security reasons, the \`${attributeName}\` can be set on the <${resolvedTagName}> element ` + `as a static attribute only. \n` + `To fix this, switch the \`${attributeName}\` binding to a static attribute ` + `in a template or in host bindings section.`;
  throw new RuntimeError(-910, errorMessage);
}
function getSecuritySensitiveSVGAnimationAttributeName(element, validationConfig) {
  for (const attributeName of element.getAttributeNames()) {
    if (attributeName.toLowerCase() !== 'attributename') {
      continue;
    }
    const attributeNameValue = element.getAttribute(attributeName);
    if (attributeNameValue !== null && validationConfig.has(attributeNameValue.toLowerCase())) {
      return attributeNameValue;
    }
  }
  return null;
}

const NG_REFLECT_ATTRS_FLAG_DEFAULT = false;
const NG_REFLECT_ATTRS_FLAG = new InjectionToken(typeof ngDevMode === 'undefined' || ngDevMode ? 'NG_REFLECT_FLAG' : '', {
  factory: () => NG_REFLECT_ATTRS_FLAG_DEFAULT
});
function provideNgReflectAttributes() {
  const providers = typeof ngDevMode === 'undefined' || ngDevMode ? [{
    provide: NG_REFLECT_ATTRS_FLAG,
    useValue: true
  }] : [];
  return makeEnvironmentProviders(providers);
}
function normalizeDebugBindingName(name) {
  name = camelCaseToDashCase(name.replace(/[$@]/g, '_'));
  return `ng-reflect-${name}`;
}
const CAMEL_CASE_REGEXP = /([A-Z])/g;
function camelCaseToDashCase(input) {
  return input.replace(CAMEL_CASE_REGEXP, (...m) => '-' + m[1].toLowerCase());
}
function normalizeDebugBindingValue(value) {
  try {
    return value != null ? value.toString().slice(0, 30) : value;
  } catch (e) {
    return '[ERROR] Exception while trying to serialize the value';
  }
}

function ɵɵresolveWindow(element) {
  return element.ownerDocument.defaultView;
}
function ɵɵresolveDocument(element) {
  return element.ownerDocument;
}
function ɵɵresolveBody(element) {
  return element.ownerDocument.body;
}
const INTERPOLATION_DELIMITER = `�`;
function maybeUnwrapFn(value) {
  if (value instanceof Function) {
    return value();
  } else {
    return value;
  }
}

const VALUE_STRING_LENGTH_LIMIT = 200;
function assertStandaloneComponentType(type) {
  assertComponentDef(type);
  const componentDef = getComponentDef(type);
  if (!componentDef.standalone) {
    throw new RuntimeError(907, `The ${stringifyForError(type)} component is not marked as standalone, ` + `but Angular expects to have a standalone component here. ` + `Please make sure the ${stringifyForError(type)} component does not have ` + `the \`standalone: false\` flag in the decorator.`);
  }
}
function assertComponentDef(type) {
  if (!getComponentDef(type)) {
    throw new RuntimeError(906, `The ${stringifyForError(type)} is not an Angular component, ` + `make sure it has the \`@Component\` decorator.`);
  }
}
function throwMultipleComponentError(tNode, first, second) {
  throw new RuntimeError(-300, `Multiple components match node with tagname ${tNode.value}: ` + `${stringifyForError(first)} and ` + `${stringifyForError(second)}`);
}
function throwErrorIfNoChangesMode(creationMode, oldValue, currValue, propName, lView) {
  const hostComponentDef = getDeclarationComponentDef(lView);
  const componentClassName = hostComponentDef?.type?.name;
  const field = propName ? ` for '${propName}'` : '';
  let msg = `ExpressionChangedAfterItHasBeenCheckedError: Expression has changed after it was checked. Previous value${field}: '${formatValue(oldValue)}'. Current value: '${formatValue(currValue)}'.${componentClassName ? ` Expression location: ${componentClassName} component` : ''}`;
  if (creationMode) {
    msg += ` It seems like the view has been created after its parent and its children have been dirty checked.` + ` Has it been created in a change detection hook?`;
  }
  throw new RuntimeError(-100, msg);
}
function formatValue(value) {
  let strValue = String(value);
  try {
    if (Array.isArray(value) || strValue === '[object Object]') {
      strValue = JSON.stringify(value);
    }
  } catch (error) {}
  return strValue.length > VALUE_STRING_LENGTH_LIMIT ? strValue.substring(0, VALUE_STRING_LENGTH_LIMIT) + '…' : strValue;
}
function constructDetailsForInterpolation(lView, rootIndex, expressionIndex, meta, changedValue) {
  const [propName, prefix, ...chunks] = meta.split(INTERPOLATION_DELIMITER);
  let oldValue = prefix,
    newValue = prefix;
  for (let i = 0; i < chunks.length; i++) {
    const slotIdx = rootIndex + i;
    oldValue += `${lView[slotIdx]}${chunks[i]}`;
    newValue += `${slotIdx === expressionIndex ? changedValue : lView[slotIdx]}${chunks[i]}`;
  }
  return {
    propName,
    oldValue,
    newValue
  };
}
function getExpressionChangedErrorDetails(lView, bindingIndex, oldValue, newValue) {
  const tData = lView[TVIEW$1].data;
  const metadata = tData[bindingIndex];
  if (typeof metadata === 'string') {
    if (metadata.indexOf(INTERPOLATION_DELIMITER) > -1) {
      return constructDetailsForInterpolation(lView, bindingIndex, bindingIndex, metadata, newValue);
    }
    return {
      propName: metadata,
      oldValue,
      newValue
    };
  }
  if (metadata === null) {
    let idx = bindingIndex - 1;
    while (typeof tData[idx] !== 'string' && tData[idx + 1] === null) {
      idx--;
    }
    const meta = tData[idx];
    if (typeof meta === 'string') {
      const matches = meta.match(new RegExp(INTERPOLATION_DELIMITER, 'g'));
      if (matches && matches.length - 1 > bindingIndex - idx) {
        return constructDetailsForInterpolation(lView, idx, bindingIndex, meta, newValue);
      }
    }
  }
  return {
    propName: undefined,
    oldValue,
    newValue
  };
}

function classIndexOf(className, classToSearch, startingIndex) {
  ngDevMode && assertNotEqual(classToSearch, '', 'can not look for "" string.');
  let end = className.length;
  while (true) {
    const foundIndex = className.indexOf(classToSearch, startingIndex);
    if (foundIndex === -1) return foundIndex;
    if (foundIndex === 0 || className.charCodeAt(foundIndex - 1) <= 32) {
      const length = classToSearch.length;
      if (foundIndex + length === end || className.charCodeAt(foundIndex + length) <= 32) {
        return foundIndex;
      }
    }
    startingIndex = foundIndex + 1;
  }
}

const NG_TEMPLATE_SELECTOR = 'ng-template';
function isCssClassMatching(tNode, attrs, cssClassToMatch, isProjectionMode) {
  ngDevMode && assertEqual(cssClassToMatch, cssClassToMatch.toLowerCase(), 'Class name expected to be lowercase.');
  let i = 0;
  if (isProjectionMode) {
    for (; i < attrs.length && typeof attrs[i] === 'string'; i += 2) {
      if (attrs[i] === 'class' && classIndexOf(attrs[i + 1].toLowerCase(), cssClassToMatch, 0) !== -1) {
        return true;
      }
    }
  } else if (isInlineTemplate(tNode)) {
    return false;
  }
  i = attrs.indexOf(1, i);
  if (i > -1) {
    let item;
    while (++i < attrs.length && typeof (item = attrs[i]) === 'string') {
      if (item.toLowerCase() === cssClassToMatch) {
        return true;
      }
    }
  }
  return false;
}
function isInlineTemplate(tNode) {
  return tNode.type === 4 && tNode.value !== NG_TEMPLATE_SELECTOR;
}
function hasTagAndTypeMatch(tNode, currentSelector, isProjectionMode) {
  const tagNameToCompare = tNode.type === 4 && !isProjectionMode ? NG_TEMPLATE_SELECTOR : tNode.value;
  return currentSelector === tagNameToCompare;
}
function isNodeMatchingSelector(tNode, selector, isProjectionMode) {
  ngDevMode && assertDefined(selector[0], 'Selector should have a tag name');
  let mode = 4;
  const nodeAttrs = tNode.attrs;
  const nameOnlyMarkerIdx = nodeAttrs !== null ? getNameOnlyMarkerIndex(nodeAttrs) : 0;
  let skipToNextSelector = false;
  for (let i = 0; i < selector.length; i++) {
    const current = selector[i];
    if (typeof current === 'number') {
      if (!skipToNextSelector && !isPositive(mode) && !isPositive(current)) {
        return false;
      }
      if (skipToNextSelector && isPositive(current)) continue;
      skipToNextSelector = false;
      mode = current | mode & 1;
      continue;
    }
    if (skipToNextSelector) continue;
    if (mode & 4) {
      mode = 2 | mode & 1;
      if (current !== '' && !hasTagAndTypeMatch(tNode, current, isProjectionMode) || current === '' && selector.length === 1) {
        if (isPositive(mode)) return false;
        skipToNextSelector = true;
      }
    } else if (mode & 8) {
      if (nodeAttrs === null || !isCssClassMatching(tNode, nodeAttrs, current, isProjectionMode)) {
        if (isPositive(mode)) return false;
        skipToNextSelector = true;
      }
    } else {
      const selectorAttrValue = selector[++i];
      const attrIndexInNode = findAttrIndexInNode(current, nodeAttrs, isInlineTemplate(tNode), isProjectionMode);
      if (attrIndexInNode === -1) {
        if (isPositive(mode)) return false;
        skipToNextSelector = true;
        continue;
      }
      if (selectorAttrValue !== '') {
        let nodeAttrValue;
        if (attrIndexInNode > nameOnlyMarkerIdx) {
          nodeAttrValue = '';
        } else {
          ngDevMode && assertNotEqual(nodeAttrs[attrIndexInNode], 0, 'We do not match directives on namespaced attributes');
          nodeAttrValue = nodeAttrs[attrIndexInNode + 1].toLowerCase();
        }
        if (mode & 2 && selectorAttrValue !== nodeAttrValue) {
          if (isPositive(mode)) return false;
          skipToNextSelector = true;
        }
      }
    }
  }
  return isPositive(mode) || skipToNextSelector;
}
function isPositive(mode) {
  return (mode & 1) === 0;
}
function findAttrIndexInNode(name, attrs, isInlineTemplate, isProjectionMode) {
  if (attrs === null) return -1;
  let i = 0;
  if (isProjectionMode || !isInlineTemplate) {
    let bindingsMode = false;
    while (i < attrs.length) {
      const maybeAttrName = attrs[i];
      if (maybeAttrName === name) {
        return i;
      } else if (maybeAttrName === 3 || maybeAttrName === 6) {
        bindingsMode = true;
      } else if (maybeAttrName === 1 || maybeAttrName === 2) {
        let value = attrs[++i];
        while (typeof value === 'string') {
          value = attrs[++i];
        }
        continue;
      } else if (maybeAttrName === 4) {
        break;
      } else if (maybeAttrName === 0) {
        i += 4;
        continue;
      }
      i += bindingsMode ? 1 : 2;
    }
    return -1;
  } else {
    return matchTemplateAttribute(attrs, name);
  }
}
function isNodeMatchingSelectorList(tNode, selector, isProjectionMode = false) {
  for (let i = 0; i < selector.length; i++) {
    if (isNodeMatchingSelector(tNode, selector[i], isProjectionMode)) {
      return true;
    }
  }
  return false;
}
function getProjectAsAttrValue(tNode) {
  const nodeAttrs = tNode.attrs;
  if (nodeAttrs != null) {
    const ngProjectAsAttrIdx = nodeAttrs.indexOf(5);
    if ((ngProjectAsAttrIdx & 1) === 0) {
      return nodeAttrs[ngProjectAsAttrIdx + 1];
    }
  }
  return null;
}
function getNameOnlyMarkerIndex(nodeAttrs) {
  for (let i = 0; i < nodeAttrs.length; i++) {
    const nodeAttr = nodeAttrs[i];
    if (isNameOnlyAttributeMarker(nodeAttr)) {
      return i;
    }
  }
  return nodeAttrs.length;
}
function matchTemplateAttribute(attrs, name) {
  let i = attrs.indexOf(4);
  if (i > -1) {
    i++;
    while (i < attrs.length) {
      const attr = attrs[i];
      if (typeof attr === 'number') return -1;
      if (attr === name) return i;
      i++;
    }
  }
  return -1;
}
function isSelectorInSelectorList(selector, list) {
  selectorListLoop: for (let i = 0; i < list.length; i++) {
    const currentSelectorInList = list[i];
    if (selector.length !== currentSelectorInList.length) {
      continue;
    }
    for (let j = 0; j < selector.length; j++) {
      if (selector[j] !== currentSelectorInList[j]) {
        continue selectorListLoop;
      }
    }
    return true;
  }
  return false;
}
function maybeWrapInNotSelector(isNegativeMode, chunk) {
  return isNegativeMode ? ':not(' + chunk.trim() + ')' : chunk;
}
function stringifyCSSSelector(selector) {
  let result = selector[0];
  let i = 1;
  let mode = 2;
  let currentChunk = '';
  let isNegativeMode = false;
  while (i < selector.length) {
    let valueOrMarker = selector[i];
    if (typeof valueOrMarker === 'string') {
      if (mode & 2) {
        const attrValue = selector[++i];
        currentChunk += '[' + valueOrMarker + (attrValue.length > 0 ? '="' + attrValue + '"' : '') + ']';
      } else if (mode & 8) {
        currentChunk += '.' + valueOrMarker;
      } else if (mode & 4) {
        currentChunk += ' ' + valueOrMarker;
      }
    } else {
      if (currentChunk !== '' && !isPositive(valueOrMarker)) {
        result += maybeWrapInNotSelector(isNegativeMode, currentChunk);
        currentChunk = '';
      }
      mode = valueOrMarker;
      isNegativeMode = isNegativeMode || !isPositive(mode);
    }
    i++;
  }
  if (currentChunk !== '') {
    result += maybeWrapInNotSelector(isNegativeMode, currentChunk);
  }
  return result;
}
function stringifyCSSSelectorList(selectorList) {
  return selectorList.map(stringifyCSSSelector).join(',');
}
function extractAttrsAndClassesFromSelector(selector) {
  const attrs = [];
  const classes = [];
  let i = 1;
  let mode = 2;
  while (i < selector.length) {
    let valueOrMarker = selector[i];
    if (typeof valueOrMarker === 'string') {
      if (mode === 2) {
        if (valueOrMarker !== '') {
          attrs.push(valueOrMarker, selector[++i]);
        }
      } else if (mode === 8) {
        classes.push(valueOrMarker);
      }
    } else {
      if (!isPositive(mode)) break;
      mode = valueOrMarker;
    }
    i++;
  }
  if (classes.length) {
    attrs.push(1, ...classes);
  }
  return attrs;
}

const NO_CHANGE = typeof ngDevMode === 'undefined' || ngDevMode ? {
  __brand__: 'NO_CHANGE'
} : {};

var RendererStyleFlags2;
(function (RendererStyleFlags2) {
  RendererStyleFlags2[RendererStyleFlags2["Important"] = 1] = "Important";
  RendererStyleFlags2[RendererStyleFlags2["DashCase"] = 2] = "DashCase";
})(RendererStyleFlags2 || (RendererStyleFlags2 = {}));

let _icuContainerIterate;
function icuContainerIterate(tIcuContainerNode, lView) {
  return _icuContainerIterate(tIcuContainerNode, lView);
}
function ensureIcuContainerVisitorLoaded(loader) {
  if (_icuContainerIterate === undefined) {
    _icuContainerIterate = loader();
  }
}

const ANIMATIONS_DISABLED = new InjectionToken(typeof ngDevMode !== 'undefined' && ngDevMode ? 'AnimationsDisabled' : '', {
  factory: () => false
});
const MAX_ANIMATION_TIMEOUT = new InjectionToken(typeof ngDevMode !== 'undefined' && ngDevMode ? 'MaxAnimationTimeout' : '', {
  factory: () => MAX_ANIMATION_TIMEOUT_DEFAULT
});
const MAX_ANIMATION_TIMEOUT_DEFAULT = 4000;

function parseCssTimeUnitsToMs(value) {
  if (!value) return 0;
  const multiplier = value.toLowerCase().indexOf('ms') > -1 ? 1 : 1000;
  return parseFloat(value) * multiplier;
}
function parseCssPropertyValue(computedStyle, name) {
  const value = computedStyle.getPropertyValue(name);
  return value.split(',').map(part => part.trim());
}
function getLongestComputedTransition(computedStyle) {
  const transitionedProperties = parseCssPropertyValue(computedStyle, 'transition-property');
  const rawDurations = parseCssPropertyValue(computedStyle, 'transition-duration');
  const rawDelays = parseCssPropertyValue(computedStyle, 'transition-delay');
  const longest = {
    propertyName: '',
    duration: 0,
    animationName: undefined
  };
  for (let i = 0; i < transitionedProperties.length; i++) {
    const duration = parseCssTimeUnitsToMs(rawDelays[i]) + parseCssTimeUnitsToMs(rawDurations[i]);
    if (duration > longest.duration) {
      longest.propertyName = transitionedProperties[i];
      longest.duration = duration;
    }
  }
  return longest;
}
function getLongestComputedAnimation(computedStyle) {
  const rawNames = parseCssPropertyValue(computedStyle, 'animation-name');
  const rawDelays = parseCssPropertyValue(computedStyle, 'animation-delay');
  const rawDurations = parseCssPropertyValue(computedStyle, 'animation-duration');
  const rawIterationCounts = parseCssPropertyValue(computedStyle, 'animation-iteration-count');
  const longest = {
    animationName: '',
    propertyName: undefined,
    duration: 0
  };
  for (let i = 0; i < rawNames.length; i++) {
    const duration = parseCssTimeUnitsToMs(rawDelays[i]) + parseCssTimeUnitsToMs(rawDurations[i]);
    const iterationCount = rawIterationCounts[i];
    if (duration > longest.duration && iterationCount !== 'infinite') {
      longest.animationName = rawNames[i];
      longest.duration = duration;
    }
  }
  return longest;
}
function isShorterThanExistingAnimation(existing, longest) {
  return existing !== undefined && existing.duration > longest.duration;
}
function longestExists(longest) {
  return (longest.animationName != undefined || longest.propertyName != undefined) && longest.duration > 0;
}
function getAnimationDuration(animation) {
  const timing = animation.effect?.getTiming();
  if (timing === undefined) return undefined;
  const animationDuration = typeof timing.duration === 'number' ? timing.duration : 0;
  let duration = (timing.delay ?? 0) + animationDuration;
  const playbackRate = animation.playbackRate;
  if (playbackRate !== undefined && playbackRate !== 0 && playbackRate !== 1) {
    duration /= Math.abs(playbackRate);
  }
  return duration;
}
function determineLongestAnimationFromComputedStyles(el, animationsMap) {
  const computedStyle = getComputedStyle(el);
  const longestAnimation = getLongestComputedAnimation(computedStyle);
  const longestTransition = getLongestComputedTransition(computedStyle);
  const longest = longestAnimation.duration > longestTransition.duration ? longestAnimation : longestTransition;
  if (isShorterThanExistingAnimation(animationsMap.get(el), longest)) return;
  if (longestExists(longest)) {
    animationsMap.set(el, longest);
  }
}
function determineLongestAnimation(el, animationsMap, areAnimationSupported) {
  if (!areAnimationSupported) return;
  const animations = el.getAnimations();
  return animations.length === 0 ? determineLongestAnimationFromComputedStyles(el, animationsMap) : determineLongestAnimationFromElementAnimations(el, animationsMap, animations);
}
function determineLongestAnimationFromElementAnimations(el, animationsMap, animations) {
  let longest = {
    animationName: undefined,
    propertyName: undefined,
    duration: 0
  };
  for (const animation of animations) {
    const timing = animation.effect?.getTiming();
    if (timing?.iterations === Infinity) {
      continue;
    }
    const duration = getAnimationDuration(animation) ?? 0;
    let propertyName;
    let animationName;
    if (animation.animationName) {
      animationName = animation.animationName;
    } else {
      propertyName = animation.transitionProperty;
    }
    if (duration >= longest.duration) {
      longest = {
        animationName,
        propertyName,
        duration
      };
    }
  }
  if (isShorterThanExistingAnimation(animationsMap.get(el), longest)) return;
  if (longestExists(longest)) {
    animationsMap.set(el, longest);
  }
}
const allLeavingAnimations = new Set();

const DEFAULT_ANIMATIONS_DISABLED = false;
const ANIMATION_DURATION_TOLERANCE_MS = 1;
const areAnimationSupported = (typeof ngServerMode === 'undefined' || !ngServerMode) && typeof document !== 'undefined' && typeof document?.documentElement?.getAnimations === 'function';
function areAnimationsDisabled(lView) {
  const injector = lView[INJECTOR];
  return injector.get(ANIMATIONS_DISABLED, DEFAULT_ANIMATIONS_DISABLED);
}
function assertAnimationTypes(value, instruction) {
  if (value == null || typeof value !== 'string' && typeof value !== 'function') {
    throw new RuntimeError(650, `'${instruction}' value must be a string of CSS classes or an animation function, got ${stringify(value)}`);
  }
}
function assertElementNodes(nativeElement, instruction) {
  if (nativeElement.nodeType !== Node.ELEMENT_NODE) {
    throw new RuntimeError(650, `'${instruction}' can only be used on an element node, got ${stringify(nativeElement.nodeType)}`);
  }
}
function trackEnterClasses(el, classList, cleanupFns) {
  const elementData = enterClassMap.get(el);
  if (elementData) {
    for (const klass of classList) {
      elementData.classList.push(klass);
    }
    for (const fn of cleanupFns) {
      elementData.cleanupFns.push(fn);
    }
  } else {
    enterClassMap.set(el, {
      classList,
      cleanupFns
    });
  }
}
function cleanupEnterClassData(element) {
  const elementData = enterClassMap.get(element);
  if (elementData) {
    for (const fn of elementData.cleanupFns) {
      fn();
    }
    enterClassMap.delete(element);
  }
  longestAnimations.delete(element);
}
const noOpAnimationComplete = () => {};
const enterClassMap = new WeakMap();
const longestAnimations = new WeakMap();
const leavingNodes = new WeakMap();
function getDeclarationView(lView) {
  if (!lView) return null;
  return lView[DECLARATION_VIEW] ?? lView;
}
const reusedNodes = new WeakSet();
function clearLeavingNodes(tNode, el) {
  const nodes = leavingNodes.get(tNode);
  if (nodes && nodes.length > 0) {
    const ix = nodes.findIndex(node => node.el === el);
    if (ix > -1) nodes.splice(ix, 1);
  }
  if (nodes?.length === 0) {
    leavingNodes.delete(tNode);
  }
}
function cancelLeavingNodes(tNode, newElement, newLView) {
  const nodes = leavingNodes.get(tNode);
  if (!nodes || nodes.length === 0) return;
  const newParent = newElement.parentNode;
  const prevSibling = newElement.previousSibling;
  const newDeclarationView = getDeclarationView(newLView);
  for (let i = nodes.length - 1; i >= 0; i--) {
    const {
      el: leavingEl,
      declarationView: leavingDeclarationView
    } = nodes[i];
    const leavingParent = leavingEl.parentNode;
    if (leavingEl === newElement) {
      nodes.splice(i, 1);
      reusedNodes.add(leavingEl);
      leavingEl.dispatchEvent(new CustomEvent('animationend', {
        detail: {
          cancel: true
        }
      }));
    } else if (prevSibling && leavingEl === prevSibling) {
      nodes.splice(i, 1);
      leavingEl.dispatchEvent(new CustomEvent('animationend', {
        detail: {
          cancel: true
        }
      }));
      leavingEl.parentNode?.removeChild(leavingEl);
    } else if (leavingParent && newParent && leavingParent !== newParent) {
      const sameLogicalView = newDeclarationView === null || leavingDeclarationView === null || newDeclarationView === leavingDeclarationView;
      if (sameLogicalView) {
        nodes.splice(i, 1);
        leavingEl.dispatchEvent(new CustomEvent('animationend', {
          detail: {
            cancel: true
          }
        }));
        leavingEl.parentNode?.removeChild(leavingEl);
      }
    }
  }
}
function trackLeavingNodes(tNode, el, lView) {
  const declarationView = getDeclarationView(lView);
  const nodes = leavingNodes.get(tNode);
  if (nodes) {
    if (!nodes.some(node => node.el === el)) {
      nodes.push({
        el,
        declarationView
      });
    }
  } else {
    leavingNodes.set(tNode, [{
      el,
      declarationView
    }]);
  }
}
function getLViewEnterAnimations(lView) {
  const animationData = lView[ANIMATIONS] ??= {};
  return animationData.enter ??= new Map();
}
function getLViewLeaveAnimations(lView) {
  const animationData = lView[ANIMATIONS] ??= {};
  return animationData.leave ??= new Map();
}
function getClassListFromValue(value) {
  let classes = typeof value === 'function' ? value() : value;
  while (typeof classes === 'function') {
    classes = classes();
  }
  let classList = Array.isArray(classes) ? classes : null;
  if (typeof classes === 'string') {
    classList = classes.trim().split(/\s+/).filter(k => k);
  }
  return classList;
}
function removeClasses(renderer, el, classList) {
  for (const item of classList) {
    renderer.removeClass(el, item);
  }
}
function addClasses(renderer, el, classList) {
  for (const item of classList) {
    renderer.addClass(el, item);
  }
}
function cancelAnimationsIfRunning(element, renderer) {
  if (!areAnimationSupported) return;
  const elementData = enterClassMap.get(element);
  if (elementData && elementData.classList.length > 0 && elementHasClassList(element, elementData.classList)) {
    removeClasses(renderer, element, elementData.classList);
  }
  cleanupEnterClassData(element);
}
function elementHasClassList(element, classList) {
  for (const className of classList) {
    if (element.classList.contains(className)) return true;
  }
  return false;
}
function getEventTarget(event) {
  return event.composedPath ? event.composedPath()[0] : event.target;
}
function isLongestAnimation(event, nativeElement) {
  const longestAnimation = longestAnimations.get(nativeElement);
  if (longestAnimation === undefined) return true;
  if (nativeElement !== getEventTarget(event)) return false;
  const eventAnimation = event.animation;
  if (eventAnimation) {
    const eventAnimationDuration = getAnimationDuration(eventAnimation);
    if (eventAnimationDuration !== undefined && eventAnimationDuration + ANIMATION_DURATION_TOLERANCE_MS < longestAnimation.duration) {
      return false;
    }
  }
  if (longestAnimation.animationName !== undefined) {
    return event.animationName === longestAnimation.animationName;
  }
  if (longestAnimation.propertyName !== undefined) {
    return longestAnimation.propertyName === 'all' || event.propertyName === longestAnimation.propertyName;
  }
  return false;
}
function addAnimationToLView(animations, tNode, fn) {
  const nodeAnimations = animations.get(tNode.index) ?? {
    animateFns: []
  };
  nodeAnimations.animateFns.push(fn);
  animations.set(tNode.index, nodeAnimations);
}
function cleanupAfterLeaveAnimations(resolvers, cleanupFns) {
  if (resolvers) {
    for (const fn of resolvers) {
      fn();
    }
  }
  for (const fn of cleanupFns) {
    fn();
  }
}
function clearLViewNodeAnimationResolvers(lView, tNode) {
  const nodeAnimations = getLViewLeaveAnimations(lView).get(tNode.index);
  if (nodeAnimations) nodeAnimations.resolvers = undefined;
}
function leaveAnimationFunctionCleanup(lView, tNode, nativeElement, resolvers, cleanupFns) {
  clearLeavingNodes(tNode, nativeElement);
  cleanupAfterLeaveAnimations(resolvers, cleanupFns);
  clearLViewNodeAnimationResolvers(lView, tNode);
}

var TracingAction;
(function (TracingAction) {
  TracingAction[TracingAction["CHANGE_DETECTION"] = 0] = "CHANGE_DETECTION";
  TracingAction[TracingAction["AFTER_NEXT_RENDER"] = 1] = "AFTER_NEXT_RENDER";
})(TracingAction || (TracingAction = {}));
const TracingService = new InjectionToken(typeof ngDevMode !== 'undefined' && ngDevMode ? 'TracingService' : '');

const markedFeatures = new Set();
function performanceMarkFeature(feature) {
  if (markedFeatures.has(feature)) {
    return;
  }
  markedFeatures.add(feature);
  performance?.mark?.('mark_feature_usage', {
    detail: {
      feature
    }
  });
}

class AfterRenderManager {
  impl = null;
  execute() {
    this.impl?.execute();
  }
  static ɵprov =
  /* @__PURE__ */
  __defineInjectable({
    token: AfterRenderManager,
    providedIn: 'root',
    factory: () => new AfterRenderManager()
  });
}
const AFTER_RENDER_PHASES = /* @__PURE__ **/(() => [0, 1, 2, 3])();
class AfterRenderImpl {
  ngZone = inject(NgZone);
  scheduler = inject(ChangeDetectionScheduler);
  errorHandler = inject(ErrorHandler, {
    optional: true
  });
  sequences = new Set();
  deferredRegistrations = new Set();
  executing = false;
  constructor() {
    inject(TracingService, {
      optional: true
    });
  }
  execute() {
    const hasSequencesToExecute = this.sequences.size > 0;
    if (hasSequencesToExecute) {
      profiler(ProfilerEvent.AfterRenderHooksStart);
    }
    this.executing = true;
    for (const phase of AFTER_RENDER_PHASES) {
      for (const sequence of this.sequences) {
        if (sequence.erroredOrDestroyed || !sequence.hooks[phase]) {
          continue;
        }
        try {
          sequence.pipelinedValue = this.ngZone.runOutsideAngular(() => this.maybeTrace(() => {
            const hookFn = sequence.hooks[phase];
            const value = hookFn(sequence.pipelinedValue);
            return value;
          }, sequence.snapshot));
        } catch (err) {
          sequence.erroredOrDestroyed = true;
          this.errorHandler?.handleError(err);
        }
      }
    }
    this.executing = false;
    for (const sequence of this.sequences) {
      sequence.afterRun();
      if (sequence.once) {
        this.sequences.delete(sequence);
        sequence.destroy();
      }
    }
    for (const sequence of this.deferredRegistrations) {
      this.sequences.add(sequence);
    }
    if (this.deferredRegistrations.size > 0) {
      this.scheduler.notify(7);
    }
    this.deferredRegistrations.clear();
    if (hasSequencesToExecute) {
      profiler(ProfilerEvent.AfterRenderHooksEnd);
    }
  }
  register(sequence) {
    const {
      view
    } = sequence;
    if (view !== undefined) {
      (view[AFTER_RENDER_SEQUENCES_TO_ADD] ??= []).push(sequence);
      markAncestorsForTraversal(view);
      view[FLAGS] |= 8192;
    } else {
      this.addSequence(sequence);
    }
  }
  addSequence(sequence) {
    if (this.executing) {
      this.deferredRegistrations.add(sequence);
    } else {
      this.sequences.add(sequence);
    }
    this.scheduler.notify(7);
  }
  unregister(sequence) {
    if (this.executing && this.sequences.has(sequence)) {
      sequence.erroredOrDestroyed = true;
      sequence.pipelinedValue = undefined;
      sequence.once = true;
    } else {
      this.sequences.delete(sequence);
      this.deferredRegistrations.delete(sequence);
    }
  }
  maybeTrace(fn, snapshot) {
    return snapshot ? snapshot.run(TracingAction.AFTER_NEXT_RENDER, fn) : fn();
  }
  static ɵprov =
  /* @__PURE__ */
  __defineInjectable({
    token: AfterRenderImpl,
    providedIn: 'root',
    factory: () => new AfterRenderImpl()
  });
}
class AfterRenderSequence {
  impl;
  hooks;
  view;
  once;
  snapshot;
  erroredOrDestroyed = false;
  pipelinedValue = undefined;
  unregisterOnDestroy;
  constructor(impl, hooks, view, once, destroyRef, snapshot = null) {
    this.impl = impl;
    this.hooks = hooks;
    this.view = view;
    this.once = once;
    this.snapshot = snapshot;
    this.unregisterOnDestroy = destroyRef?.onDestroy(() => this.destroy());
  }
  afterRun() {
    this.erroredOrDestroyed = false;
    this.pipelinedValue = undefined;
    this.snapshot?.dispose();
    this.snapshot = null;
  }
  destroy() {
    this.impl.unregister(this);
    this.unregisterOnDestroy?.();
    const scheduled = this.view?.[AFTER_RENDER_SEQUENCES_TO_ADD];
    if (scheduled) {
      this.view[AFTER_RENDER_SEQUENCES_TO_ADD] = scheduled.filter(s => s !== this);
    }
  }
}

function afterEveryRender(callbackOrSpec, options) {
  ngDevMode && assertNotInReactiveContext(afterEveryRender, 'Call `afterEveryRender` outside of a reactive context. For example, schedule the render ' + 'callback inside the component constructor`.');
  if (ngDevMode && !options?.injector) {
    assertInInjectionContext(afterEveryRender);
  }
  const injector = options?.injector ?? inject(Injector);
  if (typeof ngServerMode !== 'undefined' && ngServerMode) {
    return NOOP_AFTER_RENDER_REF;
  }
  performanceMarkFeature('NgAfterRender');
  return afterEveryRenderImpl(callbackOrSpec, injector, options, false);
}
function afterNextRender(callbackOrSpec, options) {
  if (ngDevMode && !options?.injector) {
    assertInInjectionContext(afterNextRender);
  }
  const injector = options?.injector ?? inject(Injector);
  if (typeof ngServerMode !== 'undefined' && ngServerMode) {
    return NOOP_AFTER_RENDER_REF;
  }
  performanceMarkFeature('NgAfterNextRender');
  return afterEveryRenderImpl(callbackOrSpec, injector, options, true);
}
function getHooks(callbackOrSpec) {
  if (callbackOrSpec instanceof Function) {
    return [undefined, undefined, callbackOrSpec, undefined];
  } else {
    return [callbackOrSpec.earlyRead, callbackOrSpec.write, callbackOrSpec.mixedReadWrite, callbackOrSpec.read];
  }
}
function afterEveryRenderImpl(callbackOrSpec, injector, options, once) {
  const manager = injector.get(AfterRenderManager);
  manager.impl ??= injector.get(AfterRenderImpl);
  const tracing = injector.get(TracingService, null, {
    optional: true
  });
  const destroyRef = options?.manualCleanup !== true ? injector.get(DestroyRef) : null;
  const viewContext = injector.get(ViewContext, null, {
    optional: true
  });
  const sequence = new AfterRenderSequence(manager.impl, getHooks(callbackOrSpec), viewContext?.view, once, destroyRef, tracing?.snapshot(null));
  manager.impl.register(sequence);
  return sequence;
}
const NOOP_AFTER_RENDER_REF = {
  destroy() {}
};

const ANIMATION_QUEUE = new InjectionToken(typeof ngDevMode !== 'undefined' && ngDevMode ? 'AnimationQueue' : '', {
  factory: () => {
    const injector = inject(EnvironmentInjector);
    const queue = new Set();
    injector.onDestroy(() => queue.clear());
    return {
      queue,
      isScheduled: false,
      scheduler: null,
      injector
    };
  }
});
function addToAnimationQueue(animationQueue, injector, animationFns, animationData) {
  if (Array.isArray(animationFns)) {
    for (const animateFn of animationFns) {
      animationQueue.queue.add(animateFn);
      animationData?.detachedLeaveAnimationFns?.push(animateFn);
    }
  } else {
    animationQueue.queue.add(animationFns);
    animationData?.detachedLeaveAnimationFns?.push(animationFns);
  }
  animationQueue.scheduler && animationQueue.scheduler(injector);
}
function removeAnimationsFromQueue(animationQueue, animationFns) {
  if (Array.isArray(animationFns)) {
    for (const animateFn of animationFns) {
      animationQueue.queue.delete(animateFn);
    }
  } else {
    animationQueue.queue.delete(animationFns);
  }
}
function removeFromAnimationQueue(injector, animationData) {
  const animationQueue = injector.get(ANIMATION_QUEUE);
  if (animationData.detachedLeaveAnimationFns) {
    for (const animationFn of animationData.detachedLeaveAnimationFns) {
      animationQueue.queue.delete(animationFn);
    }
    animationData.detachedLeaveAnimationFns = undefined;
  }
}
function scheduleAnimationQueue(injector) {
  const animationQueue = injector.get(ANIMATION_QUEUE);
  if (!animationQueue.isScheduled) {
    afterNextRender(() => {
      animationQueue.isScheduled = false;
      for (let animateFn of animationQueue.queue) {
        animateFn();
      }
      animationQueue.queue.clear();
    }, {
      injector: animationQueue.injector
    });
    animationQueue.isScheduled = true;
  }
}
function initializeAnimationQueueScheduler(injector) {
  const animationQueue = injector.get(ANIMATION_QUEUE);
  animationQueue.scheduler = scheduleAnimationQueue;
  animationQueue.scheduler(injector);
}
function queueEnterAnimations(injector, enterAnimations) {
  const queue = injector.get(ANIMATION_QUEUE);
  for (const [_, nodeAnimations] of enterAnimations) {
    addToAnimationQueue(queue, injector, nodeAnimations.animateFns);
  }
}

let nodeAnimationRuntime = null;
let viewDetachAnimationRuntime = null;
function maybeQueueEnterAnimation(parentLView, parent, tNode, injector) {
  nodeAnimationRuntime?.maybeQueueEnterAnimation(parentLView, parent, tNode, injector);
}
function runLeaveAnimationsWithCallback(lView, tNode, injector, callback) {
  if (nodeAnimationRuntime === null) {
    callback(false);
  } else {
    nodeAnimationRuntime.runLeaveAnimationsWithCallback(lView, tNode, injector, callback);
  }
}
function initViewDetachAnimations(view) {
  viewDetachAnimationRuntime?.initViewDetachAnimations(view);
}
function clearViewDetachAnimations(view) {
  viewDetachAnimationRuntime?.clearViewDetachAnimations(view);
}
function enableAnimationRuntimeSupport() {
  nodeAnimationRuntime ??= {
    maybeQueueEnterAnimation: maybeQueueEnterAnimationImpl,
    runLeaveAnimationsWithCallback: runLeaveAnimationsWithCallbackImpl
  };
}
function enableViewDetachAnimationsSupport() {
  viewDetachAnimationRuntime ??= {
    initViewDetachAnimations: initViewDetachAnimationsImpl,
    clearViewDetachAnimations: clearViewDetachAnimationsImpl
  };
}
function maybeQueueEnterAnimationImpl(parentLView, parent, tNode, injector) {
  const enterAnimations = parentLView?.[ANIMATIONS]?.enter;
  if (parent !== null && enterAnimations && enterAnimations.has(tNode.index)) {
    queueEnterAnimations(injector, enterAnimations);
  }
}
function runLeaveAnimationsWithCallbackImpl(lView, tNode, injector, callback) {
  let animationQueue;
  try {
    animationQueue = injector.get(ANIMATION_QUEUE);
  } catch {
    return callback(false);
  }
  const animations = lView ? lView[ANIMATIONS] ??= {} : undefined;
  if (animations?.enter?.has(tNode.index)) {
    removeAnimationsFromQueue(animationQueue, animations.enter.get(tNode.index).animateFns);
  }
  const nodesWithExitAnimations = aggregateDescendantAnimations(lView, tNode, animations);
  if (nodesWithExitAnimations.size === 0) {
    const hasNestedAnimations = lView ? hasNestedViewAnimations(lView, tNode) : false;
    if (!hasNestedAnimations) {
      return callback(false);
    }
  }
  if (lView) allLeavingAnimations.add(lView[ID]);
  addToAnimationQueue(animationQueue, injector, () => executeLeaveAnimations(lView, tNode, animations, nodesWithExitAnimations, callback), animations);
}
function aggregateDescendantAnimations(lView, tNode, animations) {
  const nodesWithExitAnimations = new Map();
  const leaveAnimations = animations?.leave;
  if (leaveAnimations && leaveAnimations.has(tNode.index)) {
    nodesWithExitAnimations.set(tNode.index, leaveAnimations.get(tNode.index));
  }
  if (lView && leaveAnimations) {
    for (const [index, animationData] of leaveAnimations) {
      if (nodesWithExitAnimations.has(index)) continue;
      const nestedTNode = lView[TVIEW$1].data[index];
      let parent = nestedTNode.parent;
      while (parent) {
        if (parent === tNode) {
          nodesWithExitAnimations.set(index, animationData);
          break;
        }
        parent = parent.parent;
      }
    }
  }
  return nodesWithExitAnimations;
}
function executeLeaveAnimations(lView, tNode, animations, nodesWithExitAnimations, callback) {
  const runningAnimations = [];
  if (animations && animations.leave) {
    for (const [index] of nodesWithExitAnimations) {
      if (!animations.leave.has(index)) continue;
      const currentAnimationData = animations.leave.get(index);
      for (const animationFn of currentAnimationData.animateFns) {
        const {
          promise
        } = animationFn();
        runningAnimations.push(promise);
      }
      animations.detachedLeaveAnimationFns = undefined;
    }
  }
  if (lView) {
    collectNestedViewAnimations(lView, tNode, runningAnimations);
  }
  if (runningAnimations.length > 0) {
    const currentAnimations = animations || lView?.[ANIMATIONS];
    if (currentAnimations) {
      const prevRunning = currentAnimations.running;
      if (prevRunning) {
        runningAnimations.push(prevRunning);
      }
      currentAnimations.running = Promise.allSettled(runningAnimations);
      runAfterLeaveAnimations(lView, currentAnimations.running, callback);
    } else {
      Promise.allSettled(runningAnimations).then(() => {
        if (lView) allLeavingAnimations.delete(lView[ID]);
        callback(true);
      });
    }
  } else {
    if (lView) allLeavingAnimations.delete(lView[ID]);
    callback(false);
  }
}
function hasNestedViewAnimations(lView, tNode) {
  if (tNode.type & 12) {
    const lContainer = lView[tNode.index];
    if (isLContainer(lContainer)) {
      for (let i = CONTAINER_HEADER_OFFSET; i < lContainer.length; i++) {
        const subView = lContainer[i];
        if (subView[TVIEW$1].type === 2) {
          if (hasViewLeaveAnimations(subView)) {
            return true;
          }
        }
      }
    }
  }
  let child = tNode.child;
  while (child) {
    if (hasNestedViewAnimations(lView, child)) {
      return true;
    }
    child = child.next;
  }
  return false;
}
function hasViewLeaveAnimations(view) {
  const animations = view[ANIMATIONS];
  if (animations?.leave && animations.leave.size > 0) {
    return true;
  }
  let child = view[TVIEW$1].firstChild;
  while (child) {
    if (hasNestedViewAnimations(view, child)) {
      return true;
    }
    child = child.next;
  }
  return false;
}
function collectNestedViewAnimations(lView, tNode, collectedPromises) {
  if (tNode.type & 12) {
    const lContainer = lView[tNode.index];
    if (isLContainer(lContainer)) {
      for (let i = CONTAINER_HEADER_OFFSET; i < lContainer.length; i++) {
        const subView = lContainer[i];
        if (subView[TVIEW$1].type === 2) {
          collectAllViewLeaveAnimations(subView, collectedPromises);
        }
      }
    }
  }
  let child = tNode.child;
  while (child) {
    collectNestedViewAnimations(lView, child, collectedPromises);
    child = child.next;
  }
}
function collectAllViewLeaveAnimations(view, collectedPromises) {
  const animations = view[ANIMATIONS];
  if (animations && animations.leave) {
    for (const animationData of animations.leave.values()) {
      for (const animationFn of animationData.animateFns) {
        const {
          promise
        } = animationFn();
        collectedPromises.push(promise);
      }
    }
  }
  let child = view[TVIEW$1].firstChild;
  while (child) {
    collectNestedViewAnimations(view, child, collectedPromises);
    child = child.next;
  }
}
function runAfterLeaveAnimations(lView, runningAnimations, callback) {
  runningAnimations.then(() => {
    if (lView[ANIMATIONS]?.running === runningAnimations) {
      lView[ANIMATIONS].running = undefined;
      allLeavingAnimations.delete(lView[ID]);
    }
    callback(true);
  });
}
function initViewDetachAnimationsImpl(view) {
  const animations = view[ANIMATIONS] ??= {};
  animations.detachedLeaveAnimationFns = [];
  let child = view[TVIEW$1].firstChild;
  while (child) {
    initNestedViewDetachAnimations(view, child);
    child = child.next;
  }
}
function initNestedViewDetachAnimations(lView, tNode) {
  if (tNode.type & 12) {
    const lContainer = lView[tNode.index];
    if (isLContainer(lContainer)) {
      for (let i = CONTAINER_HEADER_OFFSET; i < lContainer.length; i++) {
        const subView = lContainer[i];
        if (subView[TVIEW$1].type === 2) {
          initViewDetachAnimationsImpl(subView);
        }
      }
    }
  }
  let child = tNode.child;
  while (child) {
    initNestedViewDetachAnimations(lView, child);
    child = child.next;
  }
}
function clearViewDetachAnimationsImpl(view) {
  const animations = view[ANIMATIONS];
  if (animations && animations.detachedLeaveAnimationFns && animations.detachedLeaveAnimationFns.length > 0) {
    const injector = view[INJECTOR];
    removeFromAnimationQueue(injector, animations);
    allLeavingAnimations.delete(view[ID]);
    animations.detachedLeaveAnimationFns = undefined;
  } else if (animations) {
    animations.detachedLeaveAnimationFns = undefined;
  }
  let child = view[TVIEW$1].firstChild;
  while (child) {
    clearNestedViewDetachAnimations(view, child);
    child = child.next;
  }
}
function clearNestedViewDetachAnimations(lView, tNode) {
  if (tNode.type & 12) {
    const lContainer = lView[tNode.index];
    if (isLContainer(lContainer)) {
      for (let i = CONTAINER_HEADER_OFFSET; i < lContainer.length; i++) {
        const subView = lContainer[i];
        if (subView[TVIEW$1].type === 2) {
          clearViewDetachAnimationsImpl(subView);
        }
      }
    }
  }
  let child = tNode.child;
  while (child) {
    clearNestedViewDetachAnimations(lView, child);
    child = child.next;
  }
}

function applyToElementOrContainer(action, renderer, injector, parent, lNodeToHandle, tNode, beforeNode, parentLView) {
  if (lNodeToHandle != null) {
    let lContainer;
    let isComponent = false;
    if (isLContainer(lNodeToHandle)) {
      lContainer = lNodeToHandle;
    } else if (isLView(lNodeToHandle)) {
      isComponent = true;
      ngDevMode && assertDefined(lNodeToHandle[HOST], 'HOST must be defined for a component LView');
      lNodeToHandle = lNodeToHandle[HOST];
    }
    const rNode = unwrapRNode(lNodeToHandle);
    if (action === 0 && parent !== null) {
      maybeQueueEnterAnimation(parentLView, parent, tNode, injector);
      if (beforeNode == null) {
        nativeAppendChild(renderer, parent, rNode);
      } else {
        nativeInsertBefore(renderer, parent, rNode, beforeNode || null, true);
      }
    } else if (action === 1 && parent !== null) {
      nativeInsertBefore(renderer, parent, rNode, beforeNode || null, true);
      cancelLeavingNodes(tNode, rNode, parentLView);
      if (!reusedNodes.has(rNode)) {
        maybeQueueEnterAnimation(parentLView, parent, tNode, injector);
      }
    } else if (action === 2) {
      if (parentLView?.[ANIMATIONS]?.leave?.has(tNode.index)) {
        trackLeavingNodes(tNode, rNode, parentLView);
      }
      reusedNodes.delete(rNode);
      runLeaveAnimationsWithCallback(parentLView, tNode, injector, nodeHasLeaveAnimations => {
        if (reusedNodes.has(rNode)) {
          reusedNodes.delete(rNode);
          return;
        }
        nativeRemoveNode(renderer, rNode, isComponent, nodeHasLeaveAnimations);
      });
    } else if (action === 3) {
      reusedNodes.delete(rNode);
      runLeaveAnimationsWithCallback(parentLView, tNode, injector, () => {
        renderer.destroyNode(rNode);
      });
    }
    if (lContainer != null) {
      applyContainer(renderer, action, injector, lContainer, tNode, parent, beforeNode);
    }
  }
}
function removeViewFromDOM(tView, lView) {
  detachViewFromDOM(tView, lView);
  lView[HOST] = null;
  lView[T_HOST] = null;
}
function addViewToDOM(tView, parentTNode, renderer, lView, parentNativeNode, beforeNode) {
  lView[HOST] = parentNativeNode;
  lView[T_HOST] = parentTNode;
  applyView(tView, lView, renderer, 1, parentNativeNode, beforeNode);
}
function detachViewFromDOM(tView, lView) {
  lView[ENVIRONMENT].changeDetectionScheduler?.notify(9);
  applyView(tView, lView, lView[RENDERER], 2, null, null);
}
function destroyViewTree(rootView) {
  let lViewOrLContainer = rootView[CHILD_HEAD];
  if (!lViewOrLContainer) {
    return cleanUpView(rootView[TVIEW$1], rootView);
  }
  while (lViewOrLContainer) {
    let next = null;
    if (isLView(lViewOrLContainer)) {
      next = lViewOrLContainer[CHILD_HEAD];
    } else {
      ngDevMode && assertLContainer(lViewOrLContainer);
      const firstView = lViewOrLContainer[CONTAINER_HEADER_OFFSET];
      if (firstView) next = firstView;
    }
    if (!next) {
      while (lViewOrLContainer && !lViewOrLContainer[NEXT] && lViewOrLContainer !== rootView) {
        if (isLView(lViewOrLContainer)) {
          cleanUpView(lViewOrLContainer[TVIEW$1], lViewOrLContainer);
        }
        lViewOrLContainer = lViewOrLContainer[PARENT];
      }
      if (lViewOrLContainer === null) lViewOrLContainer = rootView;
      if (isLView(lViewOrLContainer)) {
        cleanUpView(lViewOrLContainer[TVIEW$1], lViewOrLContainer);
      }
      next = lViewOrLContainer && lViewOrLContainer[NEXT];
    }
    lViewOrLContainer = next;
  }
}
function detachMovedView(declarationContainer, lView) {
  ngDevMode && assertLContainer(declarationContainer);
  ngDevMode && assertDefined(declarationContainer[MOVED_VIEWS], 'A projected view should belong to a non-empty projected views collection');
  const movedViews = declarationContainer[MOVED_VIEWS];
  const declarationViewIndex = movedViews.indexOf(lView);
  movedViews.splice(declarationViewIndex, 1);
}
function destroyLView(tView, lView) {
  if (isDestroyed(lView)) {
    return;
  }
  const renderer = lView[RENDERER];
  if (renderer.destroyNode) {
    applyView(tView, lView, renderer, 3, null, null);
  }
  destroyViewTree(lView);
}
function cleanUpView(tView, lView) {
  if (isDestroyed(lView)) {
    return;
  }
  const prevConsumer = setActiveConsumer(null);
  try {
    lView[FLAGS] &= ~128;
    lView[FLAGS] |= 256;
    lView[REACTIVE_TEMPLATE_CONSUMER] && consumerDestroy(lView[REACTIVE_TEMPLATE_CONSUMER]);
    executeOnDestroys(tView, lView);
    processCleanups(tView, lView);
    if (lView[TVIEW$1].type === 1) {
      lView[RENDERER].destroy();
    }
    const declarationContainer = lView[DECLARATION_LCONTAINER];
    if (declarationContainer !== null && isLContainer(lView[PARENT])) {
      if (declarationContainer !== lView[PARENT]) {
        detachMovedView(declarationContainer, lView);
      }
      const lQueries = lView[QUERIES];
      if (lQueries !== null) {
        lQueries.detachView(tView);
      }
    }
    unregisterLView(lView);
  } finally {
    setActiveConsumer(prevConsumer);
  }
}
function processCleanups(tView, lView) {
  ngDevMode && assertNotReactive(processCleanups.name);
  const tCleanup = tView.cleanup;
  const lCleanup = lView[CLEANUP];
  if (tCleanup !== null) {
    for (let i = 0; i < tCleanup.length - 1; i += 2) {
      if (typeof tCleanup[i] === 'string') {
        const targetIdx = tCleanup[i + 3];
        ngDevMode && assertNumber(targetIdx, 'cleanup target must be a number');
        if (targetIdx >= 0) {
          lCleanup[targetIdx]();
        } else {
          lCleanup[-targetIdx].unsubscribe();
        }
        i += 2;
      } else {
        const context = lCleanup[tCleanup[i + 1]];
        tCleanup[i].call(context);
      }
    }
  }
  if (lCleanup !== null) {
    lView[CLEANUP] = null;
  }
  const destroyHooks = lView[ON_DESTROY_HOOKS];
  if (destroyHooks !== null) {
    lView[ON_DESTROY_HOOKS] = null;
    for (let i = 0; i < destroyHooks.length; i++) {
      const destroyHooksFn = destroyHooks[i];
      ngDevMode && assertFunction(destroyHooksFn, 'Expecting destroy hook to be a function.');
      destroyHooksFn();
    }
  }
  const effects = lView[EFFECTS];
  if (effects !== null) {
    lView[EFFECTS] = null;
    for (const effect of effects) {
      effect.destroy();
    }
  }
}
function executeOnDestroys(tView, lView) {
  ngDevMode && assertNotReactive(executeOnDestroys.name);
  let destroyHooks;
  if (tView != null && (destroyHooks = tView.destroyHooks) != null) {
    for (let i = 0; i < destroyHooks.length; i += 2) {
      const context = lView[destroyHooks[i]];
      if (!(context instanceof NodeInjectorFactory)) {
        const toCall = destroyHooks[i + 1];
        if (Array.isArray(toCall)) {
          for (let j = 0; j < toCall.length; j += 2) {
            const callContext = context[toCall[j]];
            const hook = toCall[j + 1];
            profiler(ProfilerEvent.LifecycleHookStart, callContext, hook);
            try {
              hook.call(callContext);
            } finally {
              profiler(ProfilerEvent.LifecycleHookEnd, callContext, hook);
            }
          }
        } else {
          profiler(ProfilerEvent.LifecycleHookStart, context, toCall);
          try {
            toCall.call(context);
          } finally {
            profiler(ProfilerEvent.LifecycleHookEnd, context, toCall);
          }
        }
      }
    }
  }
}
function getParentRElement(tView, tNode, lView) {
  if (tNode === null) {
    throw new RuntimeError(510, ngDevMode && 'getParentRElement() was called with a null TNode, so no parent element could be resolved. This usually means a TNode was never created for this node, or was already destroyed.');
  }
  return getClosestRElement(tView, tNode.parent, lView);
}
function getClosestRElement(tView, tNode, lView) {
  let parentTNode = tNode;
  while (parentTNode !== null && parentTNode.type & (8 | 32 | 128)) {
    tNode = parentTNode;
    parentTNode = tNode.parent;
  }
  if (parentTNode === null) {
    return lView[HOST];
  } else {
    ngDevMode && assertTNodeType(parentTNode, 3 | 4);
    if (isComponentHost(parentTNode)) {
      ngDevMode && assertTNodeForLView(parentTNode, lView);
      const {
        encapsulation
      } = tView.data[parentTNode.directiveStart + parentTNode.componentOffset];
      if (encapsulation === ViewEncapsulation.None || encapsulation === ViewEncapsulation.Emulated) {
        return null;
      }
    }
    return getNativeByTNode(parentTNode, lView);
  }
}
function getInsertInFrontOfRNode(parentTNode, currentTNode, lView) {
  return _getInsertInFrontOfRNodeWithI18n(parentTNode, currentTNode, lView);
}
function getInsertInFrontOfRNodeWithNoI18n(parentTNode, currentTNode, lView) {
  if (parentTNode.type & (8 | 32)) {
    return getNativeByTNode(parentTNode, lView);
  }
  return null;
}
let _getInsertInFrontOfRNodeWithI18n = getInsertInFrontOfRNodeWithNoI18n;
let _processI18nInsertBefore;
function setI18nHandling(getInsertInFrontOfRNodeWithI18n, processI18nInsertBefore) {
  _getInsertInFrontOfRNodeWithI18n = getInsertInFrontOfRNodeWithI18n;
  _processI18nInsertBefore = processI18nInsertBefore;
}
function appendChild(tView, lView, childRNode, childTNode) {
  const parentRNode = getParentRElement(tView, childTNode, lView);
  const renderer = lView[RENDERER];
  const parentTNode = childTNode.parent || lView[T_HOST];
  const anchorNode = getInsertInFrontOfRNode(parentTNode, childTNode, lView);
  if (parentRNode != null) {
    if (Array.isArray(childRNode)) {
      for (let i = 0; i < childRNode.length; i++) {
        nativeAppendOrInsertBefore(renderer, parentRNode, childRNode[i], anchorNode, false);
      }
    } else {
      nativeAppendOrInsertBefore(renderer, parentRNode, childRNode, anchorNode, false);
    }
  }
  _processI18nInsertBefore !== undefined && _processI18nInsertBefore(renderer, childTNode, lView, childRNode, parentRNode);
}
function getFirstNativeNode(lView, tNode) {
  if (tNode !== null) {
    ngDevMode && assertTNodeType(tNode, 3 | 12 | 32 | 16 | 128);
    const tNodeType = tNode.type;
    if (tNodeType & 3) {
      return getNativeByTNode(tNode, lView);
    } else if (tNodeType & 4) {
      return getBeforeNodeForView(-1, lView[tNode.index]);
    } else if (tNodeType & 8) {
      const elIcuContainerChild = tNode.child;
      if (elIcuContainerChild !== null) {
        return getFirstNativeNode(lView, elIcuContainerChild);
      } else {
        const rNodeOrLContainer = lView[tNode.index];
        if (isLContainer(rNodeOrLContainer)) {
          return getBeforeNodeForView(-1, rNodeOrLContainer);
        } else {
          return unwrapRNode(rNodeOrLContainer);
        }
      }
    } else if (tNodeType & 128) {
      return getFirstNativeNode(lView, tNode.next);
    } else if (tNodeType & 32) {
      let nextRNode = icuContainerIterate(tNode, lView);
      let rNode = nextRNode();
      return rNode || unwrapRNode(lView[tNode.index]);
    } else {
      const projectionNodes = getProjectionNodes(lView, tNode);
      if (projectionNodes !== null) {
        if (Array.isArray(projectionNodes)) {
          return projectionNodes[0];
        }
        const parentView = getLViewParent(lView[DECLARATION_COMPONENT_VIEW]);
        ngDevMode && assertParentView(parentView);
        return getFirstNativeNode(parentView, projectionNodes);
      } else {
        return getFirstNativeNode(lView, tNode.next);
      }
    }
  }
  return null;
}
function getProjectionNodes(lView, tNode) {
  if (tNode !== null) {
    const componentView = lView[DECLARATION_COMPONENT_VIEW];
    const componentHost = componentView[T_HOST];
    const slotIdx = tNode.projection;
    ngDevMode && assertProjectionSlots(lView);
    return componentHost.projection[slotIdx];
  }
  return null;
}
function getBeforeNodeForView(viewIndexInContainer, lContainer) {
  const nextViewIndex = CONTAINER_HEADER_OFFSET + viewIndexInContainer + 1;
  if (nextViewIndex < lContainer.length) {
    const lView = lContainer[nextViewIndex];
    const firstTNodeOfView = lView[TVIEW$1].firstChild;
    if (firstTNodeOfView !== null) {
      return getFirstNativeNode(lView, firstTNodeOfView);
    }
  }
  return lContainer[NATIVE];
}
function applyNodes(renderer, action, tNode, lView, parentRElement, beforeNode, isProjection) {
  while (tNode != null) {
    ngDevMode && assertTNodeForLView(tNode, lView);
    const injector = lView[INJECTOR];
    if (tNode.type === 128) {
      tNode = tNode.next;
      continue;
    }
    ngDevMode && assertTNodeType(tNode, 3 | 12 | 16 | 32);
    const rawSlotValue = lView[tNode.index];
    const tNodeType = tNode.type;
    if (isProjection) {
      if (action === 0) {
        rawSlotValue && attachPatchData(unwrapRNode(rawSlotValue), lView);
        tNode.flags |= 2;
      }
    }
    if (!isDetachedByI18n(tNode)) {
      if (tNodeType & 8) {
        applyNodes(renderer, action, tNode.child, lView, parentRElement, beforeNode, false);
        applyToElementOrContainer(action, renderer, injector, parentRElement, rawSlotValue, tNode, beforeNode, lView);
      } else if (tNodeType & 32) {
        const nextRNode = icuContainerIterate(tNode, lView);
        let rNode;
        while (rNode = nextRNode()) {
          applyToElementOrContainer(action, renderer, injector, parentRElement, rNode, tNode, beforeNode, lView);
        }
        applyToElementOrContainer(action, renderer, injector, parentRElement, rawSlotValue, tNode, beforeNode, lView);
      } else if (tNodeType & 16) {
        applyProjectionRecursive(renderer, action, lView, tNode, parentRElement, beforeNode);
      } else {
        ngDevMode && assertTNodeType(tNode, 3 | 4);
        applyToElementOrContainer(action, renderer, injector, parentRElement, rawSlotValue, tNode, beforeNode, lView);
      }
    }
    tNode = isProjection ? tNode.projectionNext : tNode.next;
  }
}
function applyView(tView, lView, renderer, action, parentRElement, beforeNode) {
  if (tView.type === 3) {
    applyForeignNodes(renderer, action, lView, parentRElement, beforeNode);
  } else {
    applyNodes(renderer, action, tView.firstChild, lView, parentRElement, beforeNode, false);
  }
}
function applyForeignNodes(renderer, action, lView, parent, beforeNode) {
  const tView = lView[TVIEW$1];
  const headTNode = tView.firstChild;
  const tailTNode = headTNode.next;
  const head = unwrapRNode(lView[headTNode.index]);
  const tail = unwrapRNode(lView[tailTNode.index]);
  const fragmentSlotIndex = tailTNode.index + 1;
  let fragment = lView[fragmentSlotIndex];
  if (action === 1 || action === 0) {
    if (parent !== null) {
      if (fragment && fragment.hasChildNodes()) {
        nativeInsertBefore(renderer, parent, fragment, beforeNode, true);
      } else {
        nativeInsertBefore(renderer, parent, head, beforeNode, true);
        nativeInsertBefore(renderer, parent, tail, beforeNode, true);
      }
    }
  } else if (action === 2) {
    if (!fragment) {
      fragment = document.createDocumentFragment();
      lView[fragmentSlotIndex] = fragment;
    }
    if (head && head.parentNode === fragment) {
      return;
    }
    let current = head;
    while (current !== null) {
      const next = current.nextSibling;
      fragment.appendChild(current);
      if (current === tail) break;
      current = next;
    }
  }
}
function applyProjection(tView, lView, tProjectionNode) {
  const renderer = lView[RENDERER];
  const parentRNode = getParentRElement(tView, tProjectionNode, lView);
  const parentTNode = tProjectionNode.parent || lView[T_HOST];
  let beforeNode = getInsertInFrontOfRNode(parentTNode, tProjectionNode, lView);
  applyProjectionRecursive(renderer, 0, lView, tProjectionNode, parentRNode, beforeNode);
}
function applyProjectionRecursive(renderer, action, lView, tProjectionNode, parentRElement, beforeNode) {
  const componentLView = lView[DECLARATION_COMPONENT_VIEW];
  const componentNode = componentLView[T_HOST];
  ngDevMode && assertEqual(typeof tProjectionNode.projection, 'number', 'expecting projection index');
  const nodeToProjectOrRNodes = componentNode.projection[tProjectionNode.projection];
  if (Array.isArray(nodeToProjectOrRNodes)) {
    for (let i = 0; i < nodeToProjectOrRNodes.length; i++) {
      const rNode = nodeToProjectOrRNodes[i];
      applyToElementOrContainer(action, renderer, lView[INJECTOR], parentRElement, rNode, tProjectionNode, beforeNode, lView);
    }
  } else {
    let nodeToProject = nodeToProjectOrRNodes;
    const projectedComponentLView = componentLView[PARENT];
    if (hasInSkipHydrationBlockFlag(tProjectionNode)) {
      nodeToProject.flags |= 128;
    }
    applyNodes(renderer, action, nodeToProject, projectedComponentLView, parentRElement, beforeNode, true);
  }
}
function applyContainer(renderer, action, injector, lContainer, tNode, parentRElement, beforeNode) {
  ngDevMode && assertLContainer(lContainer);
  const anchor = lContainer[NATIVE];
  const native = unwrapRNode(lContainer);
  if (anchor !== native) {
    applyToElementOrContainer(action, renderer, injector, parentRElement, anchor, tNode, beforeNode);
  }
  if ((lContainer[FLAGS] & 4) !== 0) {
    return;
  }
  for (let i = CONTAINER_HEADER_OFFSET; i < lContainer.length; i++) {
    const lView = lContainer[i];
    applyView(lView[TVIEW$1], lView, renderer, action, parentRElement, anchor);
  }
}
function applyStyling(renderer, isClassBased, rNode, prop, value) {
  if (isClassBased) {
    if (!value) {
      renderer.removeClass(rNode, prop);
    } else {
      renderer.addClass(rNode, prop);
    }
  } else {
    let flags = prop.indexOf('-') === -1 ? undefined : RendererStyleFlags2.DashCase;
    if (value == null) {
      renderer.removeStyle(rNode, prop, flags);
    } else {
      const isImportant = typeof value === 'string' ? value.endsWith('!important') : false;
      if (isImportant) {
        value = value.slice(0, -10);
        flags |= RendererStyleFlags2.Important;
      }
      renderer.setStyle(rNode, prop, value, flags);
    }
  }
}

function createTView(type, declTNode, templateFn, decls, vars, directives, pipes, viewQuery, schemas, constsOrFactory, ssrId) {
  const bindingStartIndex = HEADER_OFFSET + decls;
  const initialViewLength = bindingStartIndex + vars;
  const blueprint = createViewBlueprint(bindingStartIndex, initialViewLength);
  const consts = typeof constsOrFactory === 'function' ? constsOrFactory() : constsOrFactory;
  const tView = blueprint[TVIEW$1] = {
    type: type,
    blueprint: blueprint,
    template: templateFn,
    queries: null,
    viewQuery: viewQuery,
    declTNode: declTNode,
    data: blueprint.slice().fill(null, bindingStartIndex),
    bindingStartIndex: bindingStartIndex,
    expandoStartIndex: initialViewLength,
    hostBindingOpCodes: null,
    firstCreatePass: true,
    firstUpdatePass: true,
    staticViewQueries: false,
    staticContentQueries: false,
    preOrderHooks: null,
    preOrderCheckHooks: null,
    contentHooks: null,
    contentCheckHooks: null,
    viewHooks: null,
    viewCheckHooks: null,
    destroyHooks: null,
    cleanup: null,
    contentQueries: null,
    components: null,
    directiveRegistry: typeof directives === 'function' ? directives() : directives,
    pipeRegistry: typeof pipes === 'function' ? pipes() : pipes,
    firstChild: null,
    schemas: schemas,
    consts: consts,
    incompleteFirstPass: false,
    ssrId
  };
  if (ngDevMode) {
    Object.seal(tView);
  }
  return tView;
}
function createViewBlueprint(bindingStartIndex, initialViewLength) {
  const blueprint = [];
  for (let i = 0; i < initialViewLength; i++) {
    blueprint.push(i < bindingStartIndex ? null : NO_CHANGE);
  }
  return blueprint;
}
function getOrCreateComponentTView(def) {
  const tView = def.tView;
  if (tView === null || tView.incompleteFirstPass) {
    const declTNode = null;
    return def.tView = createTView(1, declTNode, def.template, def.decls, def.vars, def.directiveDefs, def.pipeDefs, def.viewQuery, def.schemas, def.consts, def.id);
  }
  return tView;
}
function createLView(parentLView, tView, context, flags, host, tHostNode, environment, renderer, injector, embeddedViewInjector, hydrationInfo) {
  const lView = tView.blueprint.slice();
  lView[HOST] = host;
  lView[FLAGS] = flags | 4 | 128 | 8 | 64 | 1024;
  if (embeddedViewInjector !== null || parentLView && parentLView[FLAGS] & 2048) {
    lView[FLAGS] |= 2048;
  }
  resetPreOrderHookFlags(lView);
  ngDevMode && tView.declTNode && parentLView && assertTNodeForLView(tView.declTNode, parentLView);
  lView[PARENT] = lView[DECLARATION_VIEW] = parentLView;
  lView[CONTEXT] = context;
  lView[ENVIRONMENT] = environment || parentLView && parentLView[ENVIRONMENT];
  ngDevMode && assertDefined(lView[ENVIRONMENT], 'LViewEnvironment is required');
  lView[RENDERER] = renderer || parentLView && parentLView[RENDERER];
  ngDevMode && assertDefined(lView[RENDERER], 'Renderer is required');
  lView[INJECTOR] = injector || parentLView && parentLView[INJECTOR] || null;
  lView[T_HOST] = tHostNode;
  lView[ID] = getUniqueLViewId();
  lView[HYDRATION] = hydrationInfo;
  lView[EMBEDDED_VIEW_INJECTOR] = embeddedViewInjector;
  ngDevMode && assertEqual(tView.type == 2 ? parentLView !== null : true, true, 'Embedded views must have parentLView');
  lView[DECLARATION_COMPONENT_VIEW] = tView.type == 2 ? parentLView[DECLARATION_COMPONENT_VIEW] : lView;
  return lView;
}
function createComponentLView(lView, hostTNode, def) {
  const native = getNativeByTNode(hostTNode, lView);
  const tView = getOrCreateComponentTView(def);
  const rendererFactory = lView[ENVIRONMENT].rendererFactory;
  const componentView = addToEndOfViewTree(lView, createLView(lView, tView, null, getInitialLViewFlagsFromDef(def), native, hostTNode, null, rendererFactory.createRenderer(native, def), null, null, null));
  return lView[hostTNode.index] = componentView;
}
function getInitialLViewFlagsFromDef(def) {
  let flags = 16;
  if (def.signals) {
    flags = 4096;
  } else if (def.onPush) {
    flags = 64;
  }
  return flags;
}
function allocExpando(tView, lView, numSlotsToAlloc, initialValue) {
  if (numSlotsToAlloc === 0) return -1;
  if (ngDevMode) {
    assertFirstCreatePass(tView);
    assertSame(tView, lView[TVIEW$1], '`LView` must be associated with `TView`!');
    assertEqual(tView.data.length, lView.length, 'Expecting LView to be same size as TView');
    assertEqual(tView.data.length, tView.blueprint.length, 'Expecting Blueprint to be same size as TView');
    assertFirstUpdatePass(tView);
  }
  const allocIdx = lView.length;
  for (let i = 0; i < numSlotsToAlloc; i++) {
    lView.push(initialValue);
    tView.blueprint.push(initialValue);
    tView.data.push(null);
  }
  return allocIdx;
}
function addToEndOfViewTree(lView, lViewOrLContainer) {
  if (lView[CHILD_HEAD]) {
    lView[CHILD_TAIL][NEXT] = lViewOrLContainer;
  } else {
    lView[CHILD_HEAD] = lViewOrLContainer;
  }
  lView[CHILD_TAIL] = lViewOrLContainer;
  return lViewOrLContainer;
}

function ɵɵadvance(delta = 1) {
  ngDevMode && assertGreaterThan(delta, 0, 'Can only advance forward');
  selectIndexInternal(getTView(), getLView(), getSelectedIndex() + delta, !!ngDevMode && isInCheckNoChangesMode());
}
function selectIndexInternal(tView, lView, index, checkNoChangesMode) {
  ngDevMode && assertIndexInDeclRange(lView[TVIEW$1], index);
  if (!checkNoChangesMode) {
    const hooksInitPhaseCompleted = (lView[FLAGS] & 3) === 3;
    if (hooksInitPhaseCompleted) {
      const preOrderCheckHooks = tView.preOrderCheckHooks;
      if (preOrderCheckHooks !== null) {
        executeCheckHooks(lView, preOrderCheckHooks, index);
      }
    } else {
      const preOrderHooks = tView.preOrderHooks;
      if (preOrderHooks !== null) {
        executeInitAndCheckHooks(lView, preOrderHooks, 0, index);
      }
    }
  }
  setSelectedIndex(index);
}

var InputFlags;
(function (InputFlags) {
  InputFlags[InputFlags["None"] = 0] = "None";
  InputFlags[InputFlags["SignalBased"] = 1] = "SignalBased";
  InputFlags[InputFlags["HasDecoratorInputTransform"] = 2] = "HasDecoratorInputTransform";
})(InputFlags || (InputFlags = {}));

function writeToDirectiveInput(def, instance, publicName, value) {
  const prevConsumer = setActiveConsumer(null);
  try {
    if (ngDevMode) {
      if (!Object.hasOwn(def.inputs, publicName)) {
        throw new Error(`ASSERTION ERROR: Directive ${def.type.name} does not have an input with a public name of "${publicName}"`);
      }
      if (instance instanceof NodeInjectorFactory) {
        throw new Error(`ASSERTION ERROR: Cannot write input to factory for type ${def.type.name}. Directive has not been created yet.`);
      }
    }
    const [privateName, flags, transform] = def.inputs[publicName];
    let inputSignalNode = null;
    if ((flags & InputFlags.SignalBased) !== 0) {
      const field = instance[privateName];
      inputSignalNode = field[SIGNAL];
    }
    if (inputSignalNode !== null && inputSignalNode.transformFn !== undefined) {
      value = inputSignalNode.transformFn(value);
    } else if (transform !== null) {
      value = transform.call(instance, value);
    }
    if (def.setInput !== null) {
      def.setInput(instance, inputSignalNode, value, publicName, privateName);
    } else {
      applyValueToInputField(instance, inputSignalNode, privateName, value);
    }
  } finally {
    setActiveConsumer(prevConsumer);
  }
}

function executeTemplate(tView, lView, templateFn, rf, context) {
  const prevSelectedIndex = getSelectedIndex();
  const isUpdatePhase = rf & 2;
  try {
    setSelectedIndex(-1);
    if (isUpdatePhase && lView.length > HEADER_OFFSET) {
      selectIndexInternal(tView, lView, HEADER_OFFSET, !!ngDevMode && isInCheckNoChangesMode());
    }
    const preHookType = isUpdatePhase ? ProfilerEvent.TemplateUpdateStart : ProfilerEvent.TemplateCreateStart;
    profiler(preHookType, context, templateFn);
    templateFn(rf, context);
  } finally {
    setSelectedIndex(prevSelectedIndex);
    const postHookType = isUpdatePhase ? ProfilerEvent.TemplateUpdateEnd : ProfilerEvent.TemplateCreateEnd;
    profiler(postHookType, context, templateFn);
  }
}
function createDirectivesInstances(tView, lView, tNode) {
  instantiateAllDirectives(tView, lView, tNode);
  if ((tNode.flags & 64) === 64) {
    invokeDirectivesHostBindings(tView, lView, tNode);
  }
}
function saveResolvedLocalsInData(viewData, tNode, localRefExtractor = getNativeByTNode) {
  const localNames = tNode.localNames;
  if (localNames !== null) {
    let localIndex = tNode.index + 1;
    for (let i = 0; i < localNames.length; i += 2) {
      const index = localNames[i + 1];
      const value = index === -1 ? localRefExtractor(tNode, viewData) : viewData[index];
      viewData[localIndex++] = value;
    }
  }
}
function locateHostElement(renderer, elementOrSelector, encapsulation, injector) {
  const preserveHostContent = injector.get(PRESERVE_HOST_CONTENT, PRESERVE_HOST_CONTENT_DEFAULT);
  const preserveContent = preserveHostContent || encapsulation === ViewEncapsulation.ShadowDom || encapsulation === ViewEncapsulation.ExperimentalIsolatedShadowDom;
  const rootElement = renderer.selectRootElement(elementOrSelector, preserveContent);
  applyRootElementTransform(rootElement);
  return rootElement;
}
function applyRootElementTransform(rootElement) {
  _applyRootElementTransformImpl(rootElement);
}
let _applyRootElementTransformImpl = () => null;
function applyRootElementTransformImpl(rootElement) {
  if (hasSkipHydrationAttrOnRElement(rootElement)) {
    clearElementContents(rootElement);
  } else {
    processTextNodeMarkersBeforeHydration(rootElement);
  }
}
function enableApplyRootElementTransformImpl() {
  _applyRootElementTransformImpl = applyRootElementTransformImpl;
}
function mapPropName(name) {
  if (name === 'class') return 'className';
  if (name === 'for') return 'htmlFor';
  if (name === 'formaction') return 'formAction';
  if (name === 'innerHtml') return 'innerHTML';
  if (name === 'readonly') return 'readOnly';
  if (name === 'tabindex') return 'tabIndex';
  return name;
}
function setPropertyAndInputs(tNode, lView, propName, value, renderer, sanitizer) {
  ngDevMode && assertNotSame(value, NO_CHANGE, 'Incoming value should never be NO_CHANGE.');
  const tView = lView[TVIEW$1];
  const hasSetInput = setAllInputsForProperty(tNode, tView, lView, propName, value);
  if (hasSetInput) {
    isComponentHost(tNode) && markDirtyIfOnPush(lView, tNode.index);
    ngDevMode && setNgReflectProperties(lView, tView, tNode, propName, value);
    return;
  }
  if (tNode.type & 3) {
    propName = mapPropName(propName);
  }
  setDomProperty(tNode, lView, propName, value, renderer, sanitizer);
}
function setDomProperty(tNode, lView, propName, value, renderer, sanitizer) {
  if (tNode.type & 3) {
    const element = getNativeByTNode(tNode, lView);
    if (ngDevMode) {
      if (lView[TVIEW$1].firstUpdatePass) {
        validateAgainstEventProperties(propName);
      }
      if (!isPropertyValid(element, propName, tNode.value, lView[TVIEW$1].schemas)) {
        handleUnknownPropertyError(propName, tNode.value, tNode.type, lView);
      }
    }
    value = sanitizer != null ? sanitizer(value, tNode.value || '', propName) : value;
    value = unwrapImgVideoSrcValue(propName, element, value);
    renderer.setProperty(element, propName, value);
  } else if (tNode.type & 12) {
    if (ngDevMode && !matchingSchemas(lView[TVIEW$1].schemas, tNode.value)) {
      handleUnknownPropertyError(propName, tNode.value, tNode.type, lView);
    }
  }
}
function unwrapImgVideoSrcValue(propName, element, value) {
  if (propName === 'src' && (element.tagName === 'IMG' || element.tagName === 'VIDEO')) {
    if (value == null) {
      return '';
    }
    return unwrapSafeValue(value);
  }
  return value;
}
function markDirtyIfOnPush(lView, viewIndex) {
  ngDevMode && assertLView(lView);
  const childComponentLView = getComponentLViewByIndex(viewIndex, lView);
  if (!(childComponentLView[FLAGS] & 16)) {
    childComponentLView[FLAGS] |= 64;
  }
}
function setNgReflectProperty(lView, tNode, attrName, value) {
  const environment = lView[ENVIRONMENT];
  if (!environment.ngReflect) {
    return;
  }
  const element = getNativeByTNode(tNode, lView);
  const renderer = lView[RENDERER];
  attrName = normalizeDebugBindingName(attrName);
  const debugValue = normalizeDebugBindingValue(value);
  if (tNode.type & 3) {
    if (value == null) {
      renderer.removeAttribute(element, attrName);
    } else {
      renderer.setAttribute(element, attrName, debugValue);
    }
  } else {
    const textContent = escapeCommentText(`bindings=${JSON.stringify({
      [attrName]: debugValue
    }, null, 2)}`);
    renderer.setValue(element, textContent);
  }
}
function setNgReflectProperties(lView, tView, tNode, publicName, value) {
  const environment = lView[ENVIRONMENT];
  if (!environment.ngReflect || !(tNode.type & (3 | 4))) {
    return;
  }
  const inputConfig = tNode.inputs?.[publicName];
  const hostInputConfig = tNode.hostDirectiveInputs?.[publicName];
  if (hostInputConfig) {
    for (let i = 0; i < hostInputConfig.length; i += 2) {
      const index = hostInputConfig[i];
      const publicName = hostInputConfig[i + 1];
      const def = tView.data[index];
      setNgReflectProperty(lView, tNode, def.inputs[publicName][0], value);
    }
  }
  if (inputConfig) {
    for (const index of inputConfig) {
      const def = tView.data[index];
      setNgReflectProperty(lView, tNode, def.inputs[publicName][0], value);
    }
  }
}
function instantiateAllDirectives(tView, lView, tNode) {
  const start = tNode.directiveStart;
  const end = tNode.directiveEnd;
  if (isComponentHost(tNode)) {
    ngDevMode && assertTNodeType(tNode, 3);
    createComponentLView(lView, tNode, tView.data[start + tNode.componentOffset]);
  }
  if (!tView.firstCreatePass) {
    getOrCreateNodeInjectorForNode(tNode, lView);
  }
  const initialInputs = tNode.initialInputs;
  for (let i = start; i < end; i++) {
    const def = tView.data[i];
    const directive = getNodeInjectable(lView, tView, i, tNode);
    attachPatchData(directive, lView);
    if (initialInputs !== null) {
      setInputsFromAttrs(lView, i - start, directive, def, tNode, initialInputs);
    }
    if (isComponentDef(def)) {
      const componentView = getComponentLViewByIndex(tNode.index, lView);
      componentView[CONTEXT] = getNodeInjectable(lView, tView, i, tNode);
    }
  }
}
function invokeDirectivesHostBindings(tView, lView, tNode) {
  const start = tNode.directiveStart;
  const end = tNode.directiveEnd;
  const elementIndex = tNode.index;
  const currentDirectiveIndex = getCurrentDirectiveIndex();
  try {
    setSelectedIndex(elementIndex);
    for (let dirIndex = start; dirIndex < end; dirIndex++) {
      const def = tView.data[dirIndex];
      const directive = lView[dirIndex];
      setCurrentDirectiveIndex(dirIndex);
      if (def.hostBindings !== null || def.hostVars !== 0 || def.hostAttrs !== null) {
        invokeHostBindingsInCreationMode(def, directive);
      }
    }
  } finally {
    setSelectedIndex(-1);
    setCurrentDirectiveIndex(currentDirectiveIndex);
  }
}
function invokeHostBindingsInCreationMode(def, directive) {
  if (def.hostBindings !== null) {
    def.hostBindings(1, directive);
  }
}
function findDirectiveDefMatches(tView, tNode) {
  ngDevMode && assertFirstCreatePass(tView);
  ngDevMode && assertTNodeType(tNode, 3 | 12);
  const registry = tView.directiveRegistry;
  let matches = null;
  if (registry) {
    for (let i = 0; i < registry.length; i++) {
      const def = registry[i];
      if (isNodeMatchingSelectorList(tNode, def.selectors, false)) {
        matches ??= [];
        if (isComponentDef(def)) {
          if (ngDevMode) {
            assertTNodeType(tNode, 2, `"${tNode.value}" tags cannot be used as component hosts. ` + `Please use a different tag to activate the ${stringify(def.type)} component.`);
            if (matches.length && isComponentDef(matches[0])) {
              throwMultipleComponentError(tNode, matches.find(isComponentDef).type, def.type);
            }
          }
          matches.unshift(def);
        } else {
          matches.push(def);
        }
      }
    }
  }
  return matches;
}
function elementAttributeInternal(tNode, lView, name, value, sanitizer, namespace) {
  if (ngDevMode) {
    assertNotSame(value, NO_CHANGE, 'Incoming value should never be NO_CHANGE.');
    assertTNodeType(tNode, 2, `Attempted to set attribute \`${name}\` on a container node. ` + `Host bindings are not valid on ng-container or ng-template.`);
  }
  const element = getNativeByTNode(tNode, lView);
  value = unwrapImgVideoSrcValue(name, element, value);
  setElementAttribute(lView[RENDERER], element, namespace, tNode.value, name, value, sanitizer);
}
function setElementAttribute(renderer, element, namespace, tagName, name, value, sanitizer) {
  if (value == null) {
    if (sanitizer != null) {
      sanitizer(value, tagName || '', name);
    }
    renderer.removeAttribute(element, name, namespace);
  } else {
    const strValue = sanitizer == null ? renderStringify(value) : sanitizer(value, tagName || '', name);
    renderer.setAttribute(element, name, strValue, namespace);
  }
}
function setInputsFromAttrs(lView, directiveIndex, instance, def, tNode, initialInputData) {
  const initialInputs = initialInputData[directiveIndex];
  if (initialInputs !== null) {
    for (let i = 0; i < initialInputs.length; i += 2) {
      const lookupName = initialInputs[i];
      const value = initialInputs[i + 1];
      writeToDirectiveInput(def, instance, lookupName, value);
      if (ngDevMode) {
        setNgReflectProperty(lView, tNode, def.inputs[lookupName][0], value);
      }
    }
  }
}
function elementLikeStartShared(tNode, lView, index, name, locateOrCreateNativeNode) {
  const adjustedIndex = HEADER_OFFSET + index;
  const tView = lView[TVIEW$1];
  const native = locateOrCreateNativeNode(tView, lView, tNode, name, index);
  lView[adjustedIndex] = native;
  setCurrentTNode(tNode, true);
  const isElement = tNode.type === 2;
  if (isElement) {
    setupStaticAttributes(lView[RENDERER], native, tNode);
    if (getElementDepthCount() === 0 || isDirectiveHost(tNode)) {
      attachPatchData(native, lView);
    }
    increaseElementDepthCount();
  } else {
    attachPatchData(native, lView);
  }
  if (wasLastNodeCreated() && (!isElement || !isDetachedByI18n(tNode))) {
    appendChild(tView, lView, native, tNode);
  }
  return tNode;
}
function elementLikeEndShared(tNode) {
  let currentTNode = tNode;
  if (isCurrentTNodeParent()) {
    setCurrentTNodeAsNotParent();
  } else {
    ngDevMode && assertHasParent(getCurrentTNode());
    currentTNode = currentTNode.parent;
    setCurrentTNode(currentTNode, false);
  }
  return currentTNode;
}
function storePropertyBindingMetadata(tData, tNode, propertyName, bindingIndex, ...interpolationParts) {
  if (tData[bindingIndex] === null) {
    if (!tNode.inputs?.[propertyName] && !tNode.hostDirectiveInputs?.[propertyName]) {
      const propBindingIdxs = tNode.propertyBindings || (tNode.propertyBindings = []);
      propBindingIdxs.push(bindingIndex);
      let bindingMetadata = propertyName;
      if (interpolationParts.length > 0) {
        bindingMetadata += INTERPOLATION_DELIMITER + interpolationParts.join(INTERPOLATION_DELIMITER);
      }
      tData[bindingIndex] = bindingMetadata;
    }
  }
}
function loadComponentRenderer(currentDef, tNode, lView) {
  if (currentDef === null || isComponentDef(currentDef)) {
    lView = unwrapLView(lView[tNode.index]);
  }
  return lView[RENDERER];
}
function handleUncaughtError(lView, error) {
  const injector = lView[INJECTOR];
  if (!injector) {
    return;
  }
  let errorHandler;
  try {
    errorHandler = injector.get(INTERNAL_APPLICATION_ERROR_HANDLER, null);
  } catch {
    errorHandler = null;
  }
  errorHandler?.(error);
}
function setAllInputsForProperty(tNode, tView, lView, publicName, value) {
  const inputs = tNode.inputs?.[publicName];
  const hostDirectiveInputs = tNode.hostDirectiveInputs?.[publicName];
  let hasMatch = false;
  if (hostDirectiveInputs) {
    for (let i = 0; i < hostDirectiveInputs.length; i += 2) {
      const index = hostDirectiveInputs[i];
      ngDevMode && assertIndexInRange(lView, index);
      const publicName = hostDirectiveInputs[i + 1];
      const def = tView.data[index];
      writeToDirectiveInput(def, lView[index], publicName, value);
      hasMatch = true;
    }
  }
  if (inputs) {
    for (const index of inputs) {
      ngDevMode && assertIndexInRange(lView, index);
      const instance = lView[index];
      const def = tView.data[index];
      writeToDirectiveInput(def, instance, publicName, value);
      hasMatch = true;
    }
  }
  return hasMatch;
}
function setDirectiveInput(tNode, tView, lView, target, publicName, value) {
  let hostIndex = null;
  let hostDirectivesStart = null;
  let hostDirectivesEnd = null;
  let hasSet = false;
  if (ngDevMode && !tNode.directiveToIndex?.has(target.type)) {
    throw new Error(`Node does not have a directive with type ${target.type.name}`);
  }
  const data = tNode.directiveToIndex.get(target.type);
  if (typeof data === 'number') {
    hostIndex = data;
  } else {
    [hostIndex, hostDirectivesStart, hostDirectivesEnd] = data;
  }
  if (hostDirectivesStart !== null && hostDirectivesEnd !== null && tNode.hostDirectiveInputs && Object.hasOwn(tNode.hostDirectiveInputs, publicName)) {
    const hostDirectiveInputs = tNode.hostDirectiveInputs[publicName];
    for (let i = 0; i < hostDirectiveInputs.length; i += 2) {
      const index = hostDirectiveInputs[i];
      if (index >= hostDirectivesStart && index <= hostDirectivesEnd) {
        ngDevMode && assertIndexInRange(lView, index);
        const def = tView.data[index];
        const hostDirectivePublicName = hostDirectiveInputs[i + 1];
        writeToDirectiveInput(def, lView[index], hostDirectivePublicName, value);
        hasSet = true;
      } else if (index > hostDirectivesEnd) {
        break;
      }
    }
  }
  if (hostIndex !== null && Object.hasOwn(target.inputs, publicName)) {
    ngDevMode && assertIndexInRange(lView, hostIndex);
    writeToDirectiveInput(target, lView[hostIndex], publicName, value);
    hasSet = true;
  }
  return hasSet;
}

function renderComponent(hostLView, componentHostIdx) {
  ngDevMode && assertEqual(isCreationMode(hostLView), true, 'Should be run in creation mode');
  const componentView = getComponentLViewByIndex(componentHostIdx, hostLView);
  const componentTView = componentView[TVIEW$1];
  syncViewWithBlueprint(componentTView, componentView);
  const hostRNode = componentView[HOST];
  if (hostRNode !== null && componentView[HYDRATION] === null) {
    componentView[HYDRATION] = retrieveHydrationInfo(hostRNode, componentView[INJECTOR]);
  }
  profiler(ProfilerEvent.ComponentStart);
  try {
    renderView(componentTView, componentView, componentView[CONTEXT]);
  } finally {
    profiler(ProfilerEvent.ComponentEnd, componentView[CONTEXT]);
  }
}
function syncViewWithBlueprint(tView, lView) {
  for (let i = lView.length; i < tView.blueprint.length; i++) {
    lView.push(tView.blueprint[i]);
  }
}
function renderView(tView, lView, context) {
  ngDevMode && assertEqual(isCreationMode(lView), true, 'Should be run in creation mode');
  ngDevMode && assertNotReactive(renderView.name);
  enterView(lView);
  try {
    const viewQuery = tView.viewQuery;
    if (viewQuery !== null) {
      executeViewQueryFn(1, viewQuery, context);
    }
    const templateFn = tView.template;
    if (templateFn !== null) {
      executeTemplate(tView, lView, templateFn, 1, context);
    }
    if (tView.firstCreatePass) {
      tView.firstCreatePass = false;
    }
    lView[QUERIES]?.finishViewCreation(tView);
    if (tView.staticContentQueries) {
      refreshContentQueries(tView, lView);
    }
    if (tView.staticViewQueries) {
      executeViewQueryFn(2, tView.viewQuery, context);
    }
    const components = tView.components;
    if (components !== null) {
      renderChildComponents(lView, components);
    }
  } catch (error) {
    if (tView.firstCreatePass) {
      tView.incompleteFirstPass = true;
      tView.firstCreatePass = false;
    }
    throw error;
  } finally {
    lView[FLAGS] &= -5;
    leaveView();
  }
}
function renderChildComponents(hostLView, components) {
  for (let i = 0; i < components.length; i++) {
    renderComponent(hostLView, components[i]);
  }
}

function createAndRenderEmbeddedLView(declarationLView, templateTNode, context, options) {
  const prevConsumer = setActiveConsumer(null);
  try {
    const embeddedTView = templateTNode.tView;
    ngDevMode && assertDefined(embeddedTView, 'TView must be defined for a template node.');
    ngDevMode && assertTNodeForLView(templateTNode, declarationLView);
    const isSignalView = declarationLView[FLAGS] & 4096;
    const viewFlags = isSignalView ? 4096 : 16;
    const embeddedLView = createLView(declarationLView, embeddedTView, context, viewFlags, null, templateTNode, null, null, options?.injector ?? null, options?.embeddedViewInjector ?? null, options?.dehydratedView ?? null);
    const declarationLContainer = declarationLView[templateTNode.index];
    ngDevMode && assertLContainer(declarationLContainer);
    embeddedLView[DECLARATION_LCONTAINER] = declarationLContainer;
    const declarationViewLQueries = declarationLView[QUERIES];
    if (declarationViewLQueries !== null) {
      embeddedLView[QUERIES] = declarationViewLQueries.createEmbeddedView(embeddedTView);
    }
    renderView(embeddedTView, embeddedLView, context);
    return embeddedLView;
  } finally {
    setActiveConsumer(prevConsumer);
  }
}
function shouldAddViewToDom(tNode, dehydratedView) {
  return !dehydratedView || dehydratedView.firstChild === null || hasInSkipHydrationBlockFlag(tNode);
}

const USE_EXHAUSTIVE_CHECK_NO_CHANGES_DEFAULT = false;
const UseExhaustiveCheckNoChanges = new InjectionToken(typeof ngDevMode !== 'undefined' && ngDevMode ? 'exhaustive checkNoChanges' : '');

function collectNativeNodes(tView, lView, tNode, result, isProjection = false) {
  if (tView.type === 3) {
    const headTNode = tView.firstChild;
    const tailTNode = headTNode.next;
    const head = unwrapRNode(lView[headTNode.index]);
    const tail = unwrapRNode(lView[tailTNode.index]);
    let current = head;
    while (current !== null) {
      result.push(current);
      if (current === tail) break;
      current = current.nextSibling;
    }
    return result;
  }
  while (tNode !== null) {
    if (tNode.type === 128) {
      tNode = isProjection ? tNode.projectionNext : tNode.next;
      continue;
    }
    ngDevMode && assertTNodeType(tNode, 3 | 12 | 16 | 32);
    const lNode = lView[tNode.index];
    if (lNode !== null) {
      if (isLContainer(lNode)) {
        const anchor = lNode[NATIVE];
        if (anchor !== lNode[HOST]) {
          result.push(unwrapRNode(lNode));
        }
        if (!(lNode[FLAGS] & 4)) {
          collectNativeNodesInLContainer(lNode, result);
        }
        result.push(anchor);
      } else {
        result.push(unwrapRNode(lNode));
      }
    }
    const tNodeType = tNode.type;
    if (tNodeType & 8) {
      collectNativeNodes(tView, lView, tNode.child, result);
    } else if (tNodeType & 32) {
      const nextRNode = icuContainerIterate(tNode, lView);
      let rNode;
      while (rNode = nextRNode()) {
        result.push(rNode);
      }
    } else if (tNodeType & 16) {
      const nodesInSlot = getProjectionNodes(lView, tNode);
      if (Array.isArray(nodesInSlot)) {
        result.push(...nodesInSlot);
      } else {
        const parentView = getLViewParent(lView[DECLARATION_COMPONENT_VIEW]);
        ngDevMode && assertParentView(parentView);
        collectNativeNodes(parentView[TVIEW$1], parentView, nodesInSlot, result, true);
      }
    }
    tNode = isProjection ? tNode.projectionNext : tNode.next;
  }
  return result;
}
function collectNativeNodesInLContainer(lContainer, result) {
  for (let i = CONTAINER_HEADER_OFFSET; i < lContainer.length; i++) {
    const lViewInAContainer = lContainer[i];
    const lViewFirstChildTNode = lViewInAContainer[TVIEW$1].firstChild;
    if (lViewFirstChildTNode !== null) {
      collectNativeNodes(lViewInAContainer[TVIEW$1], lViewInAContainer, lViewFirstChildTNode, result);
    }
  }
}

function addAfterRenderSequencesForView(lView) {
  if (lView[AFTER_RENDER_SEQUENCES_TO_ADD] !== null) {
    for (const sequence of lView[AFTER_RENDER_SEQUENCES_TO_ADD]) {
      sequence.impl.addSequence(sequence);
    }
    lView[AFTER_RENDER_SEQUENCES_TO_ADD].length = 0;
  }
}

let freeConsumers = [];
function getOrBorrowReactiveLViewConsumer(lView) {
  return lView[REACTIVE_TEMPLATE_CONSUMER] ?? borrowReactiveLViewConsumer(lView);
}
function borrowReactiveLViewConsumer(lView) {
  const consumer = freeConsumers.pop() ?? Object.create(REACTIVE_LVIEW_CONSUMER_NODE);
  consumer.lView = lView;
  return consumer;
}
function maybeReturnReactiveLViewConsumer(consumer) {
  if (consumer.lView[REACTIVE_TEMPLATE_CONSUMER] === consumer) {
    return;
  }
  consumer.lView = null;
  freeConsumers.push(consumer);
}
const REACTIVE_LVIEW_CONSUMER_NODE = {
  ...REACTIVE_NODE,
  consumerIsAlwaysLive: true,
  kind: 'template',
  consumerMarkedDirty: node => {
    markAncestorsForTraversal(node.lView);
  },
  consumerOnSignalRead() {
    this.lView[REACTIVE_TEMPLATE_CONSUMER] = this;
  }
};
function getOrCreateTemporaryConsumer(lView) {
  const consumer = lView[REACTIVE_TEMPLATE_CONSUMER] ?? Object.create(TEMPORARY_CONSUMER_NODE);
  consumer.lView = lView;
  return consumer;
}
const TEMPORARY_CONSUMER_NODE = {
  ...REACTIVE_NODE,
  consumerIsAlwaysLive: true,
  kind: 'template',
  consumerMarkedDirty: node => {
    let parent = getLViewParent(node.lView);
    while (parent && !viewShouldHaveReactiveConsumer(parent[TVIEW$1])) {
      parent = getLViewParent(parent);
    }
    if (!parent) {
      return;
    }
    markViewForRefresh(parent);
  },
  consumerOnSignalRead() {
    this.lView[REACTIVE_TEMPLATE_CONSUMER] = this;
  }
};
function viewShouldHaveReactiveConsumer(tView) {
  return tView.type !== 2;
}
function isReactiveLViewConsumer(node) {
  return node.kind === 'template';
}

function runEffectsInView(view) {
  if (view[EFFECTS] === null) {
    return;
  }
  let tryFlushEffects = true;
  while (tryFlushEffects) {
    let foundDirtyEffect = false;
    for (const effect of view[EFFECTS]) {
      if (!effect.dirty) {
        continue;
      }
      foundDirtyEffect = true;
      if (effect.zone === null || Zone.current === effect.zone) {
        effect.run();
      } else {
        effect.zone.run(() => effect.run());
      }
      if (view[EFFECTS] === null) {
        return;
      }
    }
    tryFlushEffects = foundDirtyEffect && !!(view[FLAGS] & 8192);
  }
}

const MAXIMUM_REFRESH_RERUNS$1 = 100;
function detectChangesInternal(lView, mode = 0) {
  const environment = lView[ENVIRONMENT];
  const rendererFactory = environment.rendererFactory;
  const checkNoChangesMode = !!ngDevMode && isInCheckNoChangesMode();
  if (!checkNoChangesMode) {
    rendererFactory.begin?.();
  }
  try {
    detectChangesInViewWhileDirty(lView, mode);
  } finally {
    if (!checkNoChangesMode) {
      rendererFactory.end?.();
    }
  }
}
function detectChangesInViewWhileDirty(lView, mode) {
  const lastIsRefreshingViewsValue = isRefreshingViews();
  try {
    setIsRefreshingViews(true);
    detectChangesInView(lView, mode);
    if (ngDevMode && isExhaustiveCheckNoChanges()) {
      return;
    }
    let retries = 0;
    while (requiresRefreshOrTraversal(lView)) {
      if (retries === MAXIMUM_REFRESH_RERUNS$1) {
        throw new RuntimeError(103, ngDevMode && 'Infinite change detection while trying to refresh views. ' + 'There may be components which each cause the other to require a refresh, ' + 'causing an infinite loop.');
      }
      retries++;
      detectChangesInView(lView, 1);
    }
  } finally {
    setIsRefreshingViews(lastIsRefreshingViewsValue);
  }
}
function checkNoChangesInternal(lView, exhaustive) {
  setIsInCheckNoChangesMode(exhaustive ? CheckNoChangesMode.Exhaustive : CheckNoChangesMode.OnlyDirtyViews);
  try {
    detectChangesInternal(lView);
  } finally {
    setIsInCheckNoChangesMode(CheckNoChangesMode.Off);
  }
}
function refreshView(tView, lView, templateFn, context) {
  ngDevMode && assertEqual(isCreationMode(lView), false, 'Should be run in update mode');
  if (isDestroyed(lView)) return;
  const flags = lView[FLAGS];
  const isInCheckNoChangesPass = ngDevMode && isInCheckNoChangesMode();
  const isInExhaustiveCheckNoChangesPass = ngDevMode && isExhaustiveCheckNoChanges();
  enterView(lView);
  let returnConsumerToPool = true;
  let prevConsumer = null;
  let currentConsumer = null;
  if (!isInCheckNoChangesPass) {
    if (viewShouldHaveReactiveConsumer(tView)) {
      currentConsumer = getOrBorrowReactiveLViewConsumer(lView);
      prevConsumer = consumerBeforeComputation(currentConsumer);
    } else if (getActiveConsumer() === null) {
      returnConsumerToPool = false;
      currentConsumer = getOrCreateTemporaryConsumer(lView);
      prevConsumer = consumerBeforeComputation(currentConsumer);
    } else if (lView[REACTIVE_TEMPLATE_CONSUMER]) {
      consumerDestroy(lView[REACTIVE_TEMPLATE_CONSUMER]);
      lView[REACTIVE_TEMPLATE_CONSUMER] = null;
    }
  }
  try {
    resetPreOrderHookFlags(lView);
    setBindingIndex(tView.bindingStartIndex);
    if (templateFn !== null) {
      executeTemplate(tView, lView, templateFn, 2, context);
    }
    const hooksInitPhaseCompleted = (flags & 3) === 3;
    if (!isInCheckNoChangesPass) {
      if (hooksInitPhaseCompleted) {
        const preOrderCheckHooks = tView.preOrderCheckHooks;
        if (preOrderCheckHooks !== null) {
          executeCheckHooks(lView, preOrderCheckHooks, null);
        }
      } else {
        const preOrderHooks = tView.preOrderHooks;
        if (preOrderHooks !== null) {
          executeInitAndCheckHooks(lView, preOrderHooks, 0, null);
        }
        incrementInitPhaseFlags(lView, 0);
      }
    }
    if (!isInExhaustiveCheckNoChangesPass) {
      markTransplantedViewsForRefresh(lView);
    }
    runEffectsInView(lView);
    detectChangesInEmbeddedViews(lView, 0);
    if (tView.contentQueries !== null) {
      refreshContentQueries(tView, lView);
    }
    if (!isInCheckNoChangesPass) {
      if (hooksInitPhaseCompleted) {
        const contentCheckHooks = tView.contentCheckHooks;
        if (contentCheckHooks !== null) {
          executeCheckHooks(lView, contentCheckHooks);
        }
      } else {
        const contentHooks = tView.contentHooks;
        if (contentHooks !== null) {
          executeInitAndCheckHooks(lView, contentHooks, 1);
        }
        incrementInitPhaseFlags(lView, 1);
      }
    }
    processHostBindingOpCodes(tView, lView);
    const components = tView.components;
    if (components !== null) {
      detectChangesInChildComponents(lView, components, 0);
    }
    const viewQuery = tView.viewQuery;
    if (viewQuery !== null) {
      executeViewQueryFn(2, viewQuery, context);
    }
    if (!isInCheckNoChangesPass) {
      if (hooksInitPhaseCompleted) {
        const viewCheckHooks = tView.viewCheckHooks;
        if (viewCheckHooks !== null) {
          executeCheckHooks(lView, viewCheckHooks);
        }
      } else {
        const viewHooks = tView.viewHooks;
        if (viewHooks !== null) {
          executeInitAndCheckHooks(lView, viewHooks, 2);
        }
        incrementInitPhaseFlags(lView, 2);
      }
    }
    if (tView.firstUpdatePass === true) {
      tView.firstUpdatePass = false;
    }
    if (lView[EFFECTS_TO_SCHEDULE]) {
      for (const notifyEffect of lView[EFFECTS_TO_SCHEDULE]) {
        notifyEffect();
      }
      lView[EFFECTS_TO_SCHEDULE] = null;
    }
    if (!isInCheckNoChangesPass) {
      addAfterRenderSequencesForView(lView);
      lView[FLAGS] &= ~(64 | 8);
    }
  } catch (e) {
    let handled = false;
    let errorToHandle = e;
    let currentLView = lView;
    while (currentLView !== null) {
      if (isLContainer(currentLView)) {
        currentLView = currentLView[PARENT];
        continue;
      }
      const onError = currentLView[ON_ERROR];
      if (onError) {
        try {
          const declarationInstance = lView[DECLARATION_COMPONENT_VIEW][CONTEXT];
          const declarationType = declarationInstance?.constructor;
          const details = {
            declarationInstance,
            declarationType,
            caughtBy: onError
          };
          const prevConsumer = setActiveConsumer(null);
          try {
            onError(encapsulateBoundaryError(errorToHandle), details);
          } finally {
            setActiveConsumer(prevConsumer);
          }
          handled = true;
          break;
        } catch (boundaryError) {
          errorToHandle = boundaryError;
        }
      }
      currentLView = currentLView[PARENT];
    }
    if (!handled) {
      if (!isInCheckNoChangesPass) {
        markAncestorsForTraversal(lView);
      }
      throw errorToHandle;
    }
  } finally {
    if (currentConsumer !== null) {
      consumerAfterComputation(currentConsumer, prevConsumer);
      if (returnConsumerToPool) {
        maybeReturnReactiveLViewConsumer(currentConsumer);
      }
    }
    leaveView();
  }
}
function detectChangesInEmbeddedViews(lView, mode) {
  for (let lContainer = getFirstLContainer(lView); lContainer !== null; lContainer = getNextLContainer(lContainer)) {
    for (let i = CONTAINER_HEADER_OFFSET; i < lContainer.length; i++) {
      const embeddedLView = lContainer[i];
      detectChangesInViewIfAttached(embeddedLView, mode);
    }
  }
}
function markTransplantedViewsForRefresh(lView) {
  for (let lContainer = getFirstLContainer(lView); lContainer !== null; lContainer = getNextLContainer(lContainer)) {
    if (!(lContainer[FLAGS] & 2)) continue;
    const movedViews = lContainer[MOVED_VIEWS];
    ngDevMode && assertDefined(movedViews, 'Transplanted View flags set but missing MOVED_VIEWS');
    for (let i = 0; i < movedViews.length; i++) {
      const movedLView = movedViews[i];
      markViewForRefresh(movedLView);
    }
  }
}
function detectChangesInComponent(hostLView, componentHostIdx, mode) {
  ngDevMode && assertEqual(isCreationMode(hostLView), false, 'Should be run in update mode');
  profiler(ProfilerEvent.ComponentStart);
  const componentView = getComponentLViewByIndex(componentHostIdx, hostLView);
  try {
    detectChangesInViewIfAttached(componentView, mode);
  } finally {
    profiler(ProfilerEvent.ComponentEnd, componentView[CONTEXT]);
  }
}
function detectChangesInViewIfAttached(lView, mode) {
  if (!viewAttachedToChangeDetector(lView)) {
    return;
  }
  detectChangesInView(lView, mode);
}
function detectChangesInView(lView, mode) {
  const isInCheckNoChangesPass = ngDevMode && isInCheckNoChangesMode();
  const tView = lView[TVIEW$1];
  const flags = lView[FLAGS];
  const consumer = lView[REACTIVE_TEMPLATE_CONSUMER];
  let shouldRefreshView = !!(mode === 0 && flags & 16);
  shouldRefreshView ||= !!(flags & 64 && mode === 0 && !isInCheckNoChangesPass);
  shouldRefreshView ||= !!(flags & 1024);
  shouldRefreshView ||= !!(consumer?.dirty && consumerPollProducersForChange(consumer));
  shouldRefreshView ||= !!(ngDevMode && isExhaustiveCheckNoChanges());
  if (consumer) {
    consumer.dirty = false;
  }
  lView[FLAGS] &= -9217;
  if (shouldRefreshView) {
    refreshView(tView, lView, tView.template, lView[CONTEXT]);
  } else if (flags & 8192) {
    const prevConsumer = setActiveConsumer(null);
    try {
      if (!isInCheckNoChangesPass) {
        runEffectsInView(lView);
      }
      detectChangesInEmbeddedViews(lView, 1);
      const components = tView.components;
      if (components !== null) {
        detectChangesInChildComponents(lView, components, 1);
      }
      if (!isInCheckNoChangesPass) {
        addAfterRenderSequencesForView(lView);
      }
    } finally {
      setActiveConsumer(prevConsumer);
    }
  }
}
function detectChangesInChildComponents(hostLView, components, mode) {
  for (let i = 0; i < components.length; i++) {
    detectChangesInComponent(hostLView, components[i], mode);
  }
}
function processHostBindingOpCodes(tView, lView) {
  const hostBindingOpCodes = tView.hostBindingOpCodes;
  if (hostBindingOpCodes === null) return;
  try {
    for (let i = 0; i < hostBindingOpCodes.length; i++) {
      const opCode = hostBindingOpCodes[i];
      if (opCode < 0) {
        setSelectedIndex(~opCode);
      } else {
        const directiveIdx = opCode;
        const bindingRootIndx = hostBindingOpCodes[++i];
        const hostBindingFn = hostBindingOpCodes[++i];
        setBindingRootForHostBindings(bindingRootIndx, directiveIdx);
        const context = lView[directiveIdx];
        profiler(ProfilerEvent.HostBindingsUpdateStart, context);
        try {
          hostBindingFn(2, context);
        } finally {
          profiler(ProfilerEvent.HostBindingsUpdateEnd, context);
        }
      }
    }
  } finally {
    setSelectedIndex(-1);
  }
}

function markViewDirty(lView, source) {
  const dirtyBitsToUse = isRefreshingViews() ? 64 : 1024 | 64;
  lView[ENVIRONMENT].changeDetectionScheduler?.notify(source);
  while (lView) {
    lView[FLAGS] |= dirtyBitsToUse;
    const parent = getLViewParent(lView);
    if (isRootView(lView) && !parent) {
      return lView;
    }
    lView = parent;
  }
  return null;
}

function createLContainer(hostNative, currentView, native, tNode) {
  ngDevMode && assertLView(currentView);
  const lContainer = [hostNative, true, 0, currentView, null, tNode, null, native, null, null];
  ngDevMode && assertEqual(lContainer.length, CONTAINER_HEADER_OFFSET, 'Should allocate correct number of slots for LContainer header.');
  return lContainer;
}
function getLViewFromLContainer(lContainer, index) {
  const adjustedIndex = CONTAINER_HEADER_OFFSET + index;
  if (adjustedIndex < lContainer.length) {
    const lView = lContainer[adjustedIndex];
    ngDevMode && assertLView(lView);
    return lView;
  }
  return undefined;
}
function addLViewToLContainer(lContainer, lView, index, addToDOM = true) {
  const tView = lView[TVIEW$1];
  insertView(tView, lView, lContainer, index);
  if (addToDOM) {
    const beforeNode = getBeforeNodeForView(index, lContainer);
    const renderer = lView[RENDERER];
    const parentRNode = renderer.parentNode(lContainer[NATIVE]);
    if (parentRNode !== null) {
      addViewToDOM(tView, lContainer[T_HOST], renderer, lView, parentRNode, beforeNode);
    }
  }
  const hydrationInfo = lView[HYDRATION];
  if (hydrationInfo !== null && hydrationInfo.firstChild !== null) {
    hydrationInfo.firstChild = null;
  }
}
function removeLViewFromLContainer(lContainer, index) {
  const lView = detachView(lContainer, index);
  if (lView !== undefined) {
    destroyLView(lView[TVIEW$1], lView);
  }
  return lView;
}
function detachView(lContainer, removeIndex) {
  if (lContainer.length <= CONTAINER_HEADER_OFFSET) return;
  const indexInContainer = CONTAINER_HEADER_OFFSET + removeIndex;
  const viewToDetach = lContainer[indexInContainer];
  if (viewToDetach) {
    const declarationLContainer = viewToDetach[DECLARATION_LCONTAINER];
    if (declarationLContainer !== null && declarationLContainer !== lContainer) {
      detachMovedView(declarationLContainer, viewToDetach);
    }
    if (removeIndex > 0) {
      lContainer[indexInContainer - 1][NEXT] = viewToDetach[NEXT];
    }
    const removedLView = removeFromArray(lContainer, CONTAINER_HEADER_OFFSET + removeIndex);
    removeViewFromDOM(viewToDetach[TVIEW$1], viewToDetach);
    const lQueries = removedLView[QUERIES];
    if (lQueries !== null) {
      lQueries.detachView(removedLView[TVIEW$1]);
    }
    viewToDetach[PARENT] = null;
    viewToDetach[NEXT] = null;
    viewToDetach[FLAGS] &= -129;
  }
  return viewToDetach;
}
function insertView(tView, lView, lContainer, index) {
  ngDevMode && assertLView(lView);
  ngDevMode && assertLContainer(lContainer);
  const indexInContainer = CONTAINER_HEADER_OFFSET + index;
  const containerLength = lContainer.length;
  if (index > 0) {
    lContainer[indexInContainer - 1][NEXT] = lView;
  }
  if (index < containerLength - CONTAINER_HEADER_OFFSET) {
    lView[NEXT] = lContainer[indexInContainer];
    addToArray(lContainer, CONTAINER_HEADER_OFFSET + index, lView);
  } else {
    lContainer.push(lView);
    lView[NEXT] = null;
  }
  lView[PARENT] = lContainer;
  const declarationLContainer = lView[DECLARATION_LCONTAINER];
  if (declarationLContainer !== null && lContainer !== declarationLContainer) {
    trackMovedView(declarationLContainer, lView);
  }
  const lQueries = lView[QUERIES];
  if (lQueries !== null) {
    lQueries.insertView(tView);
  }
  updateAncestorTraversalFlagsOnAttach(lView);
  lView[FLAGS] |= 128;
}
function trackMovedView(declarationContainer, lView) {
  ngDevMode && assertDefined(lView, 'LView required');
  ngDevMode && assertLContainer(declarationContainer);
  const movedViews = declarationContainer[MOVED_VIEWS];
  const parent = lView[PARENT];
  ngDevMode && assertDefined(parent, 'missing parent');
  if (isLView(parent)) {
    declarationContainer[FLAGS] |= 2;
  } else {
    const insertedComponentLView = parent[PARENT][DECLARATION_COMPONENT_VIEW];
    ngDevMode && assertDefined(insertedComponentLView, 'Missing insertedComponentLView');
    const declaredComponentLView = lView[DECLARATION_COMPONENT_VIEW];
    ngDevMode && assertDefined(declaredComponentLView, 'Missing declaredComponentLView');
    if (declaredComponentLView !== insertedComponentLView) {
      declarationContainer[FLAGS] |= 2;
    }
  }
  if (movedViews === null) {
    declarationContainer[MOVED_VIEWS] = [lView];
  } else {
    movedViews.push(lView);
  }
}

class ViewRef {
  _lView;
  _cdRefInjectingView;
  _appRef = null;
  _attachedToViewContainer = false;
  exhaustive;
  get rootNodes() {
    const lView = this._lView;
    const tView = lView[TVIEW$1];
    return collectNativeNodes(tView, lView, tView.firstChild, []);
  }
  constructor(_lView, _cdRefInjectingView) {
    this._lView = _lView;
    this._cdRefInjectingView = _cdRefInjectingView;
  }
  get context() {
    return this._lView[CONTEXT];
  }
  set context(value) {
    if (ngDevMode) {
      console.warn('Angular: Replacing the `context` object of an `EmbeddedViewRef` is deprecated.');
    }
    this._lView[CONTEXT] = value;
  }
  get destroyed() {
    return isDestroyed(this._lView);
  }
  destroy() {
    if (this._appRef) {
      this._appRef.detachView(this);
    } else if (this._attachedToViewContainer) {
      const parent = this._lView[PARENT];
      if (isLContainer(parent)) {
        const viewRefs = parent[VIEW_REFS];
        const index = viewRefs ? viewRefs.indexOf(this) : -1;
        if (index > -1) {
          ngDevMode && assertEqual(index, parent.indexOf(this._lView) - CONTAINER_HEADER_OFFSET, 'An attached view should be in the same position within its container as its ViewRef in the VIEW_REFS array.');
          detachView(parent, index);
          removeFromArray(viewRefs, index);
        }
      }
      this._attachedToViewContainer = false;
    }
    destroyLView(this._lView[TVIEW$1], this._lView);
  }
  onDestroy(callback) {
    storeLViewOnDestroy(this._lView, callback);
  }
  markForCheck() {
    markViewDirty(this._cdRefInjectingView || this._lView, 4);
  }
  detach() {
    this._lView[FLAGS] &= -129;
  }
  reattach() {
    updateAncestorTraversalFlagsOnAttach(this._lView);
    this._lView[FLAGS] |= 128;
  }
  detectChanges() {
    this._lView[FLAGS] |= 1024;
    detectChangesInternal(this._lView);
  }
  checkNoChanges() {
    if (ngDevMode) {
      try {
        this.exhaustive ??= this._lView[INJECTOR].get(UseExhaustiveCheckNoChanges, USE_EXHAUSTIVE_CHECK_NO_CHANGES_DEFAULT);
      } catch {
        this.exhaustive = USE_EXHAUSTIVE_CHECK_NO_CHANGES_DEFAULT;
      }
      checkNoChangesInternal(this._lView, this.exhaustive);
    }
  }
  attachToViewContainerRef() {
    if (this._appRef) {
      throw new RuntimeError(902, ngDevMode && 'This view is already attached directly to the ApplicationRef!');
    }
    this._attachedToViewContainer = true;
  }
  detachFromAppRef() {
    this._appRef = null;
    const isRoot = isRootView(this._lView);
    const declarationContainer = this._lView[DECLARATION_LCONTAINER];
    if (declarationContainer !== null && !isRoot) {
      detachMovedView(declarationContainer, this._lView);
    }
    detachViewFromDOM(this._lView[TVIEW$1], this._lView);
  }
  attachToAppRef(appRef) {
    if (this._attachedToViewContainer) {
      throw new RuntimeError(902, ngDevMode && 'This view is already attached to a ViewContainer!');
    }
    this._appRef = appRef;
    const isRoot = isRootView(this._lView);
    const declarationContainer = this._lView[DECLARATION_LCONTAINER];
    if (declarationContainer !== null && !isRoot) {
      trackMovedView(declarationContainer, this._lView);
    }
    updateAncestorTraversalFlagsOnAttach(this._lView);
  }
}
function isViewDirty(view) {
  return requiresRefreshOrTraversal(view._lView) || !!(view._lView[FLAGS] & 64);
}
function markForRefresh(view) {
  markViewForRefresh(view._lView);
}

class TemplateRef {
  _declarationLView;
  _declarationTContainer;
  elementRef;
  static __NG_ELEMENT_ID__ = injectTemplateRef;
  constructor(_declarationLView, _declarationTContainer, elementRef) {
    this._declarationLView = _declarationLView;
    this._declarationTContainer = _declarationTContainer;
    this.elementRef = elementRef;
  }
  get ssrId() {
    return this._declarationTContainer.tView?.ssrId || null;
  }
  createEmbeddedView(context, injector) {
    return this.createEmbeddedViewImpl(context, injector);
  }
  createEmbeddedViewImpl(context, injector, dehydratedView) {
    const embeddedLView = createAndRenderEmbeddedLView(this._declarationLView, this._declarationTContainer, context, {
      embeddedViewInjector: injector,
      dehydratedView
    });
    return new ViewRef(embeddedLView);
  }
}
function injectTemplateRef() {
  return createTemplateRef(getCurrentTNode(), getLView());
}
function createTemplateRef(hostTNode, hostLView) {
  if (hostTNode.type & 4) {
    ngDevMode && assertDefined(hostTNode.tView, 'TView must be allocated');
    return new TemplateRef(hostLView, hostTNode, createElementRef(hostTNode, hostLView));
  }
  return null;
}

const AT_THIS_LOCATION = '<-- AT THIS LOCATION';
const THIRD_PARTY_SCRIPTS_URL = `/guide/hydration#third-party-scripts-with-dom-manipulation`;
function getFriendlyStringFromTNodeType(tNodeType) {
  switch (tNodeType) {
    case 4:
      return 'view container';
    case 2:
      return 'element';
    case 8:
      return 'ng-container';
    case 32:
      return 'icu';
    case 64:
      return 'i18n';
    case 16:
      return 'projection';
    case 1:
      return 'text';
    case 128:
      return '@let';
    default:
      return '<unknown>';
  }
}
function validateMatchingNode(node, nodeType, tagName, lView, tNode, isViewContainerAnchor = false) {
  if (!node || node.nodeType !== nodeType || node.nodeType === Node.ELEMENT_NODE && node.tagName.toLowerCase() !== tagName?.toLowerCase()) {
    const expectedNode = shortRNodeDescription(nodeType, tagName, null);
    let header = `During hydration Angular expected ${expectedNode} but `;
    const hostComponentDef = getDeclarationComponentDef(lView);
    const componentClassName = hostComponentDef?.type?.name;
    const expectedDom = describeExpectedDom(lView, tNode, isViewContainerAnchor);
    const expected = `Angular expected this DOM:\n\n${expectedDom}\n\n`;
    let actual = '';
    const componentHostElement = unwrapRNode(lView[HOST]);
    if (!node) {
      header += `the node was not found.\n\n`;
      markRNodeAsHavingHydrationMismatch(componentHostElement, expectedDom);
    } else {
      const actualNode = shortRNodeDescription(node.nodeType, node.tagName ?? null, node.textContent ?? null);
      header += `found ${actualNode}.\n\n`;
      const actualDom = describeDomFromNode(node);
      actual = `Actual DOM is:\n\n${actualDom}\n\n`;
      markRNodeAsHavingHydrationMismatch(componentHostElement, expectedDom, actualDom);
    }
    const footer = getHydrationErrorFooter(componentClassName);
    let message = header + expected + actual + getHydrationAttributeNote() + footer;
    if (!node || node && isLikelyExternalSourceNode(node)) {
      message += `Note: It looks like this mismatch may have been caused by a third-party script or ` + `browser extension that modified the DOM outside of Angular's control. ` + `Angular hydration does not support nodes injected or removed outside of the Angular-managed DOM. ` + `Note: If you know which element in the DOM this will be inserted, consider adding ngSkipHydration to prevent this error. \n\n`;
    }
    throw new RuntimeError(-500, message);
  }
}
function validateSiblingNodeExists(node) {
  validateNodeExists(node);
  if (!node.nextSibling) {
    const header = 'During hydration Angular expected more sibling nodes to be present.\n\n';
    const actual = `Actual DOM is:\n\n${describeDomFromNode(node)}\n\n`;
    const footer = getHydrationErrorFooter();
    const message = header + actual + footer;
    markRNodeAsHavingHydrationMismatch(node, '', actual);
    throw new RuntimeError(-501, message);
  }
}
function validateNodeExists(node, lView = null, tNode = null) {
  if (!node) {
    const header = 'During hydration, Angular expected an element to be present at this location.\n\n';
    let expected = '';
    let footer = '';
    if (lView !== null && tNode !== null) {
      expected = describeExpectedDom(lView, tNode, false);
      footer = getHydrationErrorFooter();
      markRNodeAsHavingHydrationMismatch(unwrapRNode(lView[HOST]), expected, '');
    }
    throw new RuntimeError(-502, `${header}${expected}\n\n${footer}`);
  }
}
function nodeNotFoundError(lView, tNode) {
  const header = 'During serialization, Angular was unable to find an element in the DOM:\n\n';
  const expected = `${describeExpectedDom(lView, tNode, false)}\n\n`;
  const footer = getHydrationErrorFooter();
  throw new RuntimeError(-502, header + expected + footer);
}
function nodeNotFoundAtPathError(host, path) {
  const header = `During hydration Angular was unable to locate a node ` + `using the "${path}" path, starting from the ${describeRNode(host)} node.\n\n`;
  const footer = getHydrationErrorFooter();
  markRNodeAsHavingHydrationMismatch(host);
  throw new RuntimeError(-502, header + footer);
}
function unsupportedProjectionOfDomNodes(rNode) {
  const header = 'During serialization, Angular detected DOM nodes ' + 'that were created outside of Angular context and provided as projectable nodes ' + '(likely via `ViewContainerRef.createComponent` or `createComponent` APIs). ' + 'Hydration is not supported for such cases, consider refactoring the code to avoid ' + 'this pattern or using `ngSkipHydration` on the host element of the component.\n\n';
  const actual = `${describeDomFromNode(rNode)}\n\n`;
  const message = header + actual + getHydrationAttributeNote();
  return new RuntimeError(-503, message);
}
function invalidSkipHydrationHost(rNode) {
  const header = 'The `ngSkipHydration` flag is applied on a node ' + "that doesn't act as a component host. Hydration can be " + 'skipped only on per-component basis.\n\n';
  const actual = `${describeDomFromNode(rNode)}\n\n`;
  const footer = 'Please move the `ngSkipHydration` attribute to the component host element.\n\n';
  const message = header + actual + footer;
  return new RuntimeError(-504, message);
}
function stringifyTNodeAttrs(tNode) {
  const results = [];
  if (tNode.attrs) {
    for (let i = 0; i < tNode.attrs.length;) {
      const attrName = tNode.attrs[i++];
      if (typeof attrName == 'number') {
        break;
      }
      const attrValue = tNode.attrs[i++];
      results.push(`${attrName}="${shorten(attrValue)}"`);
    }
  }
  return results.join(' ');
}
const internalAttrs = new Set(['ngh', 'ng-version', 'ng-server-context']);
function stringifyRNodeAttrs(rNode) {
  const results = [];
  for (let i = 0; i < rNode.attributes.length; i++) {
    const attr = rNode.attributes[i];
    if (internalAttrs.has(attr.name)) continue;
    results.push(`${attr.name}="${shorten(attr.value)}"`);
  }
  return results.join(' ');
}
function describeTNode(tNode, innerContent = '…') {
  switch (tNode.type) {
    case 1:
      const content = tNode.value ? `(${tNode.value})` : '';
      return `#text${content}`;
    case 2:
      const attrs = stringifyTNodeAttrs(tNode);
      const tag = tNode.value.toLowerCase();
      return `<${tag}${attrs ? ' ' + attrs : ''}>${innerContent}</${tag}>`;
    case 8:
      return '<!-- ng-container -->';
    case 4:
      return '<!-- container -->';
    default:
      const typeAsString = getFriendlyStringFromTNodeType(tNode.type);
      return `#node(${typeAsString})`;
  }
}
function describeRNode(rNode, innerContent = '…') {
  const node = rNode;
  switch (node.nodeType) {
    case Node.ELEMENT_NODE:
      const tag = node.tagName.toLowerCase();
      const attrs = stringifyRNodeAttrs(node);
      return `<${tag}${attrs ? ' ' + attrs : ''}>${innerContent}</${tag}>`;
    case Node.TEXT_NODE:
      const content = node.textContent ? shorten(node.textContent) : '';
      return `#text${content ? `(${content})` : ''}`;
    case Node.COMMENT_NODE:
      return `<!-- ${shorten(node.textContent ?? '')} -->`;
    default:
      return `#node(${node.nodeType})`;
  }
}
function describeExpectedDom(lView, tNode, isViewContainerAnchor) {
  const spacer = '  ';
  let content = '';
  if (tNode.prev) {
    content += spacer + '…\n';
    content += spacer + describeTNode(tNode.prev) + '\n';
  } else if (tNode.type && tNode.type & 12) {
    content += spacer + '…\n';
  }
  if (isViewContainerAnchor) {
    content += spacer + describeTNode(tNode) + '\n';
    content += spacer + `<!-- container -->  ${AT_THIS_LOCATION}\n`;
  } else {
    content += spacer + describeTNode(tNode) + `  ${AT_THIS_LOCATION}\n`;
  }
  content += spacer + '…\n';
  const parentRNode = tNode.type ? getParentRElement(lView[TVIEW$1], tNode, lView) : null;
  if (parentRNode) {
    content = describeRNode(parentRNode, '\n' + content);
  }
  return content;
}
function describeDomFromNode(node) {
  const spacer = '  ';
  let content = '';
  const currentNode = node;
  if (currentNode.previousSibling) {
    content += spacer + '…\n';
    content += spacer + describeRNode(currentNode.previousSibling) + '\n';
  }
  content += spacer + describeRNode(currentNode) + `  ${AT_THIS_LOCATION}\n`;
  if (node.nextSibling) {
    content += spacer + '…\n';
  }
  if (node.parentNode) {
    content = describeRNode(currentNode.parentNode, '\n' + content);
  }
  return content;
}
function shortRNodeDescription(nodeType, tagName, textContent) {
  switch (nodeType) {
    case Node.ELEMENT_NODE:
      return `<${tagName.toLowerCase()}>`;
    case Node.TEXT_NODE:
      const content = textContent ? ` (with the "${shorten(textContent)}" content)` : '';
      return `a text node${content}`;
    case Node.COMMENT_NODE:
      return 'a comment node';
    default:
      return `#node(nodeType=${nodeType})`;
  }
}
function getHydrationErrorFooter(componentClassName) {
  const componentInfo = componentClassName ? `the "${componentClassName}"` : 'corresponding';
  return `To fix this problem:\n` + `  * check ${componentInfo} component for hydration-related issues\n` + `  * check to see if your template has valid HTML structure\n` + `  * check if there are any third-party scripts that manipulate the DOM. More info: ${DOC_PAGE_BASE_URL}${THIRD_PARTY_SCRIPTS_URL}\n` + `  * or skip hydration by adding the \`ngSkipHydration\` attribute ` + `to its host node in a template\n\n`;
}
function isLikelyExternalSourceNode(rNode) {
  const node = rNode;
  if (node.nodeType !== Node.ELEMENT_NODE) {
    return false;
  }
  if (readPatchedData(node)) {
    return false;
  }
  return true;
}
function getHydrationAttributeNote() {
  return 'Note: attributes are only displayed to better represent the DOM' + ' but have no effect on hydration mismatches.\n\n';
}
function stripNewlines(input) {
  return input.replace(/\s+/gm, '');
}
function shorten(input, maxLength = 50) {
  if (!input) {
    return '';
  }
  input = stripNewlines(input);
  return input.length > maxLength ? `${input.substring(0, maxLength - 1)}…` : input;
}
function describeDomNode(node) {
  const textContent = node.textContent?.slice(0, 50);
  return textContent ? `${node.nodeName} ("${textContent}")` : node.nodeName;
}

function getInsertInFrontOfRNodeWithI18n(parentTNode, currentTNode, lView) {
  const tNodeInsertBeforeIndex = currentTNode.insertBeforeIndex;
  const insertBeforeIndex = Array.isArray(tNodeInsertBeforeIndex) ? tNodeInsertBeforeIndex[0] : tNodeInsertBeforeIndex;
  if (insertBeforeIndex === null) {
    return getInsertInFrontOfRNodeWithNoI18n(parentTNode, currentTNode, lView);
  } else {
    ngDevMode && assertIndexInRange(lView, insertBeforeIndex);
    return unwrapRNode(lView[insertBeforeIndex]);
  }
}
function processI18nInsertBefore(renderer, childTNode, lView, childRNode, parentRElement) {
  const tNodeInsertBeforeIndex = childTNode.insertBeforeIndex;
  if (Array.isArray(tNodeInsertBeforeIndex)) {
    ngDevMode && assertDomNode(childRNode);
    let i18nParent = childRNode;
    let anchorRNode = null;
    if (!(childTNode.type & 3)) {
      anchorRNode = i18nParent;
      i18nParent = parentRElement;
    }
    if (i18nParent !== null && childTNode.componentOffset === -1) {
      for (let i = 1; i < tNodeInsertBeforeIndex.length; i++) {
        const i18nChild = lView[tNodeInsertBeforeIndex[i]];
        nativeInsertBefore(renderer, i18nParent, i18nChild, anchorRNode, false);
      }
    }
  }
}

function getOrCreateTNode(tView, index, type, name, attrs) {
  ngDevMode && index !== 0 && assertGreaterThanOrEqual(index, HEADER_OFFSET, "TNodes can't be in the LView header.");
  ngDevMode && assertPureTNodeType(type);
  let tNode = tView.data[index];
  if (tNode === null) {
    tNode = createTNodeAtIndex(tView, index, type, name, attrs);
    if (isInI18nBlock()) {
      tNode.flags |= 32;
    }
  } else if (tNode.type & 64) {
    tNode.type = type;
    tNode.value = name;
    tNode.attrs = attrs;
    const parent = getCurrentParentTNode();
    tNode.injectorIndex = parent === null ? -1 : parent.injectorIndex;
    ngDevMode && assertTNodeForTView(tNode, tView);
    ngDevMode && assertEqual(index, tNode.index, 'Expecting same index');
  }
  setCurrentTNode(tNode, true);
  return tNode;
}
function createTNodeAtIndex(tView, index, type, name, attrs) {
  const currentTNode = getCurrentTNodePlaceholderOk();
  const isParent = isCurrentTNodeParent();
  const parent = isParent ? currentTNode : currentTNode && currentTNode.parent;
  const tNode = tView.data[index] = createTNode(tView, parent, type, index, name, attrs);
  linkTNodeInTView(tView, tNode, currentTNode, isParent);
  return tNode;
}
function linkTNodeInTView(tView, tNode, currentTNode, isParent) {
  if (tView.firstChild === null) {
    tView.firstChild = tNode;
  }
  if (currentTNode !== null) {
    if (isParent) {
      if (currentTNode.child == null && tNode.parent !== null) {
        currentTNode.child = tNode;
      }
    } else {
      if (currentTNode.next === null) {
        currentTNode.next = tNode;
        tNode.prev = currentTNode;
      }
    }
  }
}
function createTNode(tView, tParent, type, index, value, attrs) {
  ngDevMode && index !== 0 && assertGreaterThanOrEqual(index, HEADER_OFFSET, "TNodes can't be in the LView header.");
  ngDevMode && assertNotSame(attrs, undefined, "'undefined' is not valid value for 'attrs'");
  ngDevMode && tParent && assertTNodeForTView(tParent, tView);
  let injectorIndex = tParent ? tParent.injectorIndex : -1;
  let flags = 0;
  if (isInSkipHydrationBlock$1()) {
    flags |= 128;
  }
  const tNode = {
    type,
    index,
    insertBeforeIndex: null,
    injectorIndex,
    directiveStart: -1,
    directiveEnd: -1,
    directiveStylingLast: -1,
    componentOffset: -1,
    controlDirectiveIndex: -1,
    customControlIndex: -1,
    propertyBindings: null,
    flags,
    providerIndexes: 0,
    value: value,
    namespace: getNamespace(),
    attrs: attrs,
    mergedAttrs: null,
    localNames: null,
    initialInputs: null,
    inputs: null,
    hostDirectiveInputs: null,
    outputs: null,
    hostDirectiveOutputs: null,
    directiveToIndex: null,
    tView: null,
    next: null,
    prev: null,
    projectionNext: null,
    child: null,
    parent: tParent,
    projection: null,
    styles: null,
    stylesWithoutHost: null,
    residualStyles: undefined,
    classes: null,
    classesWithoutHost: null,
    residualClasses: undefined,
    classBindings: 0,
    styleBindings: 0
  };
  if (ngDevMode) {
    Object.seal(tNode);
  }
  return tNode;
}

function addTNodeAndUpdateInsertBeforeIndex(previousTNodes, newTNode) {
  ngDevMode && assertEqual(newTNode.insertBeforeIndex, null, 'We expect that insertBeforeIndex is not set');
  previousTNodes.push(newTNode);
  if (previousTNodes.length > 1) {
    for (let i = previousTNodes.length - 2; i >= 0; i--) {
      const existingTNode = previousTNodes[i];
      if (!isI18nText(existingTNode)) {
        if (isNewTNodeCreatedBefore(existingTNode, newTNode) && getInsertBeforeIndex(existingTNode) === null) {
          setInsertBeforeIndex(existingTNode, newTNode.index);
        }
      }
    }
  }
}
function isI18nText(tNode) {
  return !(tNode.type & 64);
}
function isNewTNodeCreatedBefore(existingTNode, newTNode) {
  return isI18nText(newTNode) || existingTNode.index > newTNode.index;
}
function getInsertBeforeIndex(tNode) {
  const index = tNode.insertBeforeIndex;
  return Array.isArray(index) ? index[0] : index;
}
function setInsertBeforeIndex(tNode, value) {
  const index = tNode.insertBeforeIndex;
  if (Array.isArray(index)) {
    index[0] = value;
  } else {
    setI18nHandling(getInsertInFrontOfRNodeWithI18n, processI18nInsertBefore);
    tNode.insertBeforeIndex = value;
  }
}

const CURRENT_CASE_LVIEW_INDEX = getClosureSafeProperty({
  currentCaseLViewIndex: getClosureSafeProperty
});
const TVIEW = getClosureSafeProperty({
  tView: getClosureSafeProperty
});
function getTIcu(tView, index) {
  const value = tView.data[index];
  if (value === null || typeof value === 'string') return null;
  if (ngDevMode && !(Object.hasOwn(value, TVIEW) || Object.hasOwn(value, CURRENT_CASE_LVIEW_INDEX))) {
    throwError("We expect to get 'null'|'TIcu'|'TIcuContainer', but got: " + value);
  }
  const tIcu = Object.hasOwn(value, CURRENT_CASE_LVIEW_INDEX) ? value : value.value;
  ngDevMode && assertTIcu(tIcu);
  return tIcu;
}
function setTIcu(tView, index, tIcu) {
  const tNode = tView.data[index];
  ngDevMode && assertEqual(tNode === null || Object.hasOwn(tNode, TVIEW), true, "We expect to get 'null'|'TIcuContainer'");
  if (tNode === null) {
    tView.data[index] = tIcu;
  } else {
    ngDevMode && assertTNodeType(tNode, 32);
    tNode.value = tIcu;
  }
}
function setTNodeInsertBeforeIndex(tNode, index) {
  ngDevMode && assertTNode(tNode);
  let insertBeforeIndex = tNode.insertBeforeIndex;
  if (insertBeforeIndex === null) {
    setI18nHandling(getInsertInFrontOfRNodeWithI18n, processI18nInsertBefore);
    insertBeforeIndex = tNode.insertBeforeIndex = [null, index];
  } else {
    assertEqual(Array.isArray(insertBeforeIndex), true, 'Expecting array here');
    insertBeforeIndex.push(index);
  }
}
function createTNodePlaceholder(tView, previousTNodes, index) {
  const tNode = createTNodeAtIndex(tView, index, 64, null, null);
  addTNodeAndUpdateInsertBeforeIndex(previousTNodes, tNode);
  return tNode;
}
function getCurrentICUCaseIndex(tIcu, lView) {
  const currentCase = lView[tIcu.currentCaseLViewIndex];
  return currentCase === null ? currentCase : currentCase < 0 ? ~currentCase : currentCase;
}
function getParentFromIcuCreateOpCode(mergedCode) {
  return mergedCode >>> 17;
}
function getRefFromIcuCreateOpCode(mergedCode) {
  return (mergedCode & 131070) >>> 1;
}
function getInstructionFromIcuCreateOpCode(mergedCode) {
  return mergedCode & 1;
}
function icuCreateOpCode(opCode, parentIdx, refIdx) {
  ngDevMode && assertGreaterThanOrEqual(parentIdx, 0, 'Missing parent index');
  ngDevMode && assertGreaterThan(refIdx, 0, 'Missing ref index');
  return opCode | parentIdx << 17 | refIdx << 1;
}
function isRootTemplateMessage(subTemplateIndex) {
  return subTemplateIndex === -1;
}

function enterIcu(state, tIcu, lView) {
  state.index = 0;
  const currentCase = getCurrentICUCaseIndex(tIcu, lView);
  if (currentCase !== null) {
    ngDevMode && assertNumberInRange(currentCase, 0, tIcu.cases.length - 1);
    state.removes = tIcu.remove[currentCase];
  } else {
    state.removes = EMPTY_ARRAY;
  }
}
function icuContainerIteratorNext(state) {
  if (state.index < state.removes.length) {
    const removeOpCode = state.removes[state.index++];
    ngDevMode && assertNumber(removeOpCode, 'Expecting OpCode number');
    if (removeOpCode > 0) {
      const rNode = state.lView[removeOpCode];
      ngDevMode && assertDomNode(rNode);
      return rNode;
    } else {
      state.stack.push(state.index, state.removes);
      const tIcuIndex = ~removeOpCode;
      const tIcu = state.lView[TVIEW$1].data[tIcuIndex];
      ngDevMode && assertTIcu(tIcu);
      enterIcu(state, tIcu, state.lView);
      return icuContainerIteratorNext(state);
    }
  } else {
    if (state.stack.length === 0) {
      state.lView = undefined;
      return null;
    } else {
      state.removes = state.stack.pop();
      state.index = state.stack.pop();
      return icuContainerIteratorNext(state);
    }
  }
}
function loadIcuContainerVisitor() {
  const _state = {
    stack: [],
    index: -1
  };
  function icuContainerIteratorStart(tIcuContainerNode, lView) {
    _state.lView = lView;
    while (_state.stack.length) _state.stack.pop();
    ngDevMode && assertTNodeForLView(tIcuContainerNode, lView);
    enterIcu(_state, tIcuContainerNode.value, lView);
    return icuContainerIteratorNext.bind(null, _state);
  }
  return icuContainerIteratorStart;
}
function createIcuIterator(tIcu, lView) {
  const state = {
    stack: [],
    index: -1,
    lView
  };
  ngDevMode && assertTIcu(tIcu);
  enterIcu(state, tIcu, lView);
  return icuContainerIteratorNext.bind(null, state);
}

const REF_EXTRACTOR_REGEXP = /* @__PURE__ */(() => {
  return new RegExp(`^(\\d+)*(${REFERENCE_NODE_BODY}|${REFERENCE_NODE_HOST})*(.*)`);
})();
function compressNodeLocation(referenceNode, path) {
  const result = [referenceNode];
  for (const segment of path) {
    const lastIdx = result.length - 1;
    if (lastIdx > 0 && result[lastIdx - 1] === segment) {
      const value = result[lastIdx] || 1;
      result[lastIdx] = value + 1;
    } else {
      result.push(segment, '');
    }
  }
  return result.join('');
}
function decompressNodeLocation(path) {
  const matches = path.match(REF_EXTRACTOR_REGEXP);
  const [_, refNodeId, refNodeName, rest] = matches;
  const ref = refNodeId ? parseInt(refNodeId, 10) : refNodeName;
  const steps = [];
  for (const [_, step, count] of rest.matchAll(/(f|n)(\d*)/g)) {
    const repeat = parseInt(count, 10) || 1;
    steps.push(step, repeat);
  }
  return [ref, ...steps];
}

function isFirstElementInNgContainer(tNode) {
  return !tNode.prev && tNode.parent?.type === 8;
}
function getNoOffsetIndex(tNode) {
  return tNode.index - HEADER_OFFSET;
}
function isDisconnectedNode(tNode, lView) {
  return !(tNode.type & (16 | 128)) && !!lView[tNode.index] && isDisconnectedRNode(unwrapRNode(lView[tNode.index]));
}
function isDisconnectedRNode(rNode) {
  return !!rNode && !rNode.isConnected;
}
function locateI18nRNodeByIndex(hydrationInfo, noOffsetIndex) {
  const i18nNodes = hydrationInfo.i18nNodes;
  if (i18nNodes) {
    return i18nNodes.get(noOffsetIndex);
  }
  return undefined;
}
function tryLocateRNodeByPath(hydrationInfo, lView, noOffsetIndex) {
  const nodes = hydrationInfo.data[NODES];
  const path = nodes?.[noOffsetIndex];
  return path ? locateRNodeByPath(path, lView) : null;
}
function locateNextRNode(hydrationInfo, tView, lView, tNode) {
  const noOffsetIndex = getNoOffsetIndex(tNode);
  let native = locateI18nRNodeByIndex(hydrationInfo, noOffsetIndex);
  if (native === undefined) {
    const nodes = hydrationInfo.data[NODES];
    if (nodes?.[noOffsetIndex]) {
      native = locateRNodeByPath(nodes[noOffsetIndex], lView);
    } else if (tView.firstChild === tNode) {
      native = hydrationInfo.firstChild;
    } else {
      const previousTNodeParent = tNode.prev === null;
      const previousTNode = tNode.prev ?? tNode.parent;
      ngDevMode && assertDefined(previousTNode, 'Unexpected state: current TNode does not have a connection ' + 'to the previous node or a parent node.');
      if (isFirstElementInNgContainer(tNode)) {
        const noOffsetParentIndex = getNoOffsetIndex(tNode.parent);
        native = getSegmentHead(hydrationInfo, noOffsetParentIndex);
      } else {
        let previousRElement = getNativeByTNode(previousTNode, lView);
        if (previousTNodeParent) {
          native = previousRElement.firstChild;
        } else {
          const noOffsetPrevSiblingIndex = getNoOffsetIndex(previousTNode);
          const segmentHead = getSegmentHead(hydrationInfo, noOffsetPrevSiblingIndex);
          if (previousTNode.type === 2 && segmentHead) {
            const numRootNodesToSkip = calcSerializedContainerSize(hydrationInfo, noOffsetPrevSiblingIndex);
            const nodesToSkip = numRootNodesToSkip + 1;
            native = siblingAfter(nodesToSkip, segmentHead);
          } else {
            native = previousRElement.nextSibling;
          }
        }
      }
    }
  }
  return native;
}
function siblingAfter(skip, from) {
  let currentNode = from;
  for (let i = 0; i < skip; i++) {
    ngDevMode && validateSiblingNodeExists(currentNode);
    if (currentNode == null) {
      throw new RuntimeError(-501, ngDevMode && 'During hydration Angular expected more sibling nodes to be present. This usually means the client-rendered DOM no longer matches the server-rendered HTML.');
    }
    currentNode = currentNode.nextSibling;
  }
  return currentNode;
}
function stringifyNavigationInstructions(instructions) {
  const container = [];
  for (let i = 0; i < instructions.length; i += 2) {
    const step = instructions[i];
    const repeat = instructions[i + 1];
    for (let r = 0; r < repeat; r++) {
      container.push(step === NODE_NAVIGATION_STEP_FIRST_CHILD ? 'firstChild' : 'nextSibling');
    }
  }
  return container.join('.');
}
function navigateToNode(from, instructions) {
  let node = from;
  for (let i = 0; i < instructions.length; i += 2) {
    const step = instructions[i];
    const repeat = instructions[i + 1];
    for (let r = 0; r < repeat; r++) {
      if (ngDevMode && !node) {
        throw nodeNotFoundAtPathError(from, stringifyNavigationInstructions(instructions));
      }
      if (!node) {
        throw new RuntimeError(509, ngDevMode && 'During hydration Angular was unable to locate a node using a recorded navigation path. This usually means the client-rendered DOM no longer matches the server-rendered HTML.');
      }
      switch (step) {
        case NODE_NAVIGATION_STEP_FIRST_CHILD:
          node = node.firstChild;
          break;
        case NODE_NAVIGATION_STEP_NEXT_SIBLING:
          node = node.nextSibling;
          break;
      }
    }
  }
  if (ngDevMode && !node) {
    throw nodeNotFoundAtPathError(from, stringifyNavigationInstructions(instructions));
  }
  if (!node) {
    throw new RuntimeError(509, ngDevMode && 'During hydration Angular was unable to locate a node using a recorded navigation path. This usually means the client-rendered DOM no longer matches the server-rendered HTML.');
  }
  return node;
}
function locateRNodeByPath(path, lView) {
  const [referenceNode, ...navigationInstructions] = decompressNodeLocation(path);
  let ref;
  if (referenceNode === REFERENCE_NODE_HOST) {
    ref = lView[DECLARATION_COMPONENT_VIEW][HOST];
  } else if (referenceNode === REFERENCE_NODE_BODY) {
    ref = ɵɵresolveBody(lView[DECLARATION_COMPONENT_VIEW][HOST]);
  } else {
    const parentElementId = Number(referenceNode);
    ref = unwrapRNode(lView[parentElementId + HEADER_OFFSET]);
  }
  return navigateToNode(ref, navigationInstructions);
}
function navigateBetween(start, finish) {
  if (start === finish) {
    return [];
  } else if (start.parentElement == null || finish.parentElement == null) {
    return null;
  } else if (start.parentElement === finish.parentElement) {
    return navigateBetweenSiblings(start, finish);
  } else {
    const parent = finish.parentElement;
    const parentPath = navigateBetween(start, parent);
    const childPath = navigateBetween(parent.firstChild, finish);
    if (!parentPath || !childPath) return null;
    return [...parentPath, NODE_NAVIGATION_STEP_FIRST_CHILD, ...childPath];
  }
}
function navigateBetweenSiblings(start, finish) {
  const nav = [];
  let node = null;
  for (node = start; node != null && node !== finish; node = node.nextSibling) {
    nav.push(NODE_NAVIGATION_STEP_NEXT_SIBLING);
  }
  return node == null ? null : nav;
}
function calcPathBetween(from, to, fromNodeName) {
  const path = navigateBetween(from, to);
  return path === null ? null : compressNodeLocation(fromNodeName, path);
}
function calcPathForNode(tNode, lView, excludedParentNodes) {
  let parentTNode = tNode.parent;
  let parentIndex;
  let parentRNode;
  let referenceNodeName;
  while (parentTNode !== null && (isDisconnectedNode(parentTNode, lView) || excludedParentNodes?.has(parentTNode.index))) {
    parentTNode = parentTNode.parent;
  }
  if (parentTNode === null || !(parentTNode.type & 3)) {
    parentIndex = referenceNodeName = REFERENCE_NODE_HOST;
    parentRNode = lView[DECLARATION_COMPONENT_VIEW][HOST];
  } else {
    parentIndex = parentTNode.index;
    parentRNode = unwrapRNode(lView[parentIndex]);
    referenceNodeName = renderStringify(parentIndex - HEADER_OFFSET);
  }
  let rNode = unwrapRNode(lView[tNode.index]);
  if (tNode.type & (12 | 32)) {
    const firstRNode = getFirstNativeNode(lView, tNode);
    if (firstRNode) {
      rNode = firstRNode;
    }
  }
  let path = calcPathBetween(parentRNode, rNode, referenceNodeName);
  if (path === null && parentRNode !== rNode) {
    const body = parentRNode.ownerDocument.body;
    path = calcPathBetween(body, rNode, REFERENCE_NODE_BODY);
    if (path === null) {
      throw nodeNotFoundError(lView, tNode);
    }
  }
  return path;
}
function gatherDeferBlocksCommentNodes(doc, node) {
  const commentNodesIterator = doc.createNodeIterator(node, NodeFilter.SHOW_COMMENT, {
    acceptNode
  });
  let currentNode;
  const nodesByBlockId = new Map();
  while (currentNode = commentNodesIterator.nextNode()) {
    const nghPattern = 'ngh=';
    const content = currentNode?.textContent;
    const nghIdx = content?.indexOf(nghPattern) ?? -1;
    if (nghIdx > -1) {
      const nghValue = content.substring(nghIdx + nghPattern.length).trim();
      ngDevMode && assertEqual(nghValue.startsWith('d'), true, 'Invalid defer block id found in a comment node.');
      nodesByBlockId.set(nghValue, currentNode);
    }
  }
  return nodesByBlockId;
}
function acceptNode(node) {
  return node.textContent?.trimStart().startsWith('ngh=') ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_REJECT;
}

let _isI18nHydrationSupportEnabled = false;
let _prepareI18nBlockForHydrationImpl = () => {};
function setIsI18nHydrationSupportEnabled(enabled) {
  _isI18nHydrationSupportEnabled = enabled;
}
function isI18nHydrationSupportEnabled() {
  return _isI18nHydrationSupportEnabled;
}
function prepareI18nBlockForHydration(lView, index, parentTNode, subTemplateIndex) {
  _prepareI18nBlockForHydrationImpl(lView, index, parentTNode, subTemplateIndex);
}
function enablePrepareI18nBlockForHydrationImpl() {
  _prepareI18nBlockForHydrationImpl = prepareI18nBlockForHydrationImpl;
}
function isI18nHydrationEnabled(injector) {
  injector = injector ?? inject(Injector);
  return injector.get(IS_I18N_HYDRATION_ENABLED, false);
}
function getOrComputeI18nChildren(tView, context) {
  let i18nChildren = context.i18nChildren.get(tView);
  if (i18nChildren === undefined) {
    i18nChildren = collectI18nChildren(tView);
    context.i18nChildren.set(tView, i18nChildren);
  }
  return i18nChildren;
}
function collectI18nChildren(tView) {
  const children = new Set();
  function collectI18nViews(node) {
    children.add(node.index);
    switch (node.kind) {
      case 1:
      case 2:
        {
          for (const childNode of node.children) {
            collectI18nViews(childNode);
          }
          break;
        }
      case 3:
        {
          for (const caseNodes of node.cases) {
            for (const caseNode of caseNodes) {
              collectI18nViews(caseNode);
            }
          }
          break;
        }
    }
  }
  for (let i = HEADER_OFFSET; i < tView.bindingStartIndex; i++) {
    const tI18n = tView.data[i];
    if (!tI18n || !tI18n.ast) {
      continue;
    }
    for (const node of tI18n.ast) {
      collectI18nViews(node);
    }
  }
  return children.size === 0 ? null : children;
}
function trySerializeI18nBlock(lView, index, context) {
  if (!context.isI18nHydrationEnabled) {
    return null;
  }
  const tView = lView[TVIEW$1];
  const tI18n = tView.data[index];
  if (!tI18n || !tI18n.ast) {
    return null;
  }
  const parentTNode = tView.data[tI18n.parentTNodeIndex];
  if (parentTNode && isI18nInSkipHydrationBlock(parentTNode)) {
    return null;
  }
  const serializedI18nBlock = {
    caseQueue: [],
    disconnectedNodes: new Set(),
    disjointNodes: new Set()
  };
  serializeI18nBlock(lView, serializedI18nBlock, context, tI18n.ast);
  return serializedI18nBlock.caseQueue.length === 0 && serializedI18nBlock.disconnectedNodes.size === 0 && serializedI18nBlock.disjointNodes.size === 0 ? null : serializedI18nBlock;
}
function serializeI18nBlock(lView, serializedI18nBlock, context, nodes) {
  let prevRNode = null;
  for (const node of nodes) {
    const nextRNode = serializeI18nNode(lView, serializedI18nBlock, context, node);
    if (nextRNode) {
      if (isDisjointNode(prevRNode, nextRNode)) {
        serializedI18nBlock.disjointNodes.add(node.index - HEADER_OFFSET);
      }
      prevRNode = nextRNode;
    }
  }
  return prevRNode;
}
function isDisjointNode(prevNode, nextNode) {
  return prevNode && prevNode.nextSibling !== nextNode;
}
function serializeI18nNode(lView, serializedI18nBlock, context, node) {
  const maybeRNode = unwrapRNode(lView[node.index]);
  if (!maybeRNode || isDisconnectedRNode(maybeRNode)) {
    serializedI18nBlock.disconnectedNodes.add(node.index - HEADER_OFFSET);
    return null;
  }
  const rNode = maybeRNode;
  switch (node.kind) {
    case 0:
      {
        processTextNodeBeforeSerialization(context, rNode);
        break;
      }
    case 1:
    case 2:
      {
        serializeI18nBlock(lView, serializedI18nBlock, context, node.children);
        break;
      }
    case 3:
      {
        const currentCase = lView[node.currentCaseLViewIndex];
        if (currentCase != null) {
          const caseIdx = currentCase < 0 ? ~currentCase : currentCase;
          serializedI18nBlock.caseQueue.push(caseIdx);
          serializeI18nBlock(lView, serializedI18nBlock, context, node.cases[caseIdx]);
        }
        break;
      }
  }
  return getFirstNativeNodeForI18nNode(lView, node);
}
function getFirstNativeNodeForI18nNode(lView, node) {
  const tView = lView[TVIEW$1];
  const maybeTNode = tView.data[node.index];
  if (isTNodeShape(maybeTNode)) {
    return getFirstNativeNode(lView, maybeTNode);
  } else if (node.kind === 3) {
    const icuIterator = createIcuIterator(maybeTNode, lView);
    let rNode = icuIterator();
    return rNode ?? unwrapRNode(lView[node.index]);
  } else {
    return unwrapRNode(lView[node.index]) ?? null;
  }
}
function setCurrentNode(state, node) {
  state.currentNode = node;
}
function appendI18nNodeToCollection(context, state, astNode) {
  const noOffsetIndex = astNode.index - HEADER_OFFSET;
  const {
    disconnectedNodes
  } = context;
  const currentNode = state.currentNode;
  if (state.isConnected) {
    context.i18nNodes.set(noOffsetIndex, currentNode);
    disconnectedNodes.delete(noOffsetIndex);
  } else {
    disconnectedNodes.add(noOffsetIndex);
  }
  return currentNode;
}
function skipSiblingNodes(state, skip) {
  let currentNode = state.currentNode;
  for (let i = 0; i < skip; i++) {
    if (!currentNode) {
      break;
    }
    currentNode = currentNode?.nextSibling ?? null;
  }
  return currentNode;
}
function forkHydrationState(state, nextNode) {
  return {
    currentNode: nextNode,
    isConnected: state.isConnected
  };
}
function prepareI18nBlockForHydrationImpl(lView, index, parentTNode, subTemplateIndex) {
  const hydrationInfo = lView[HYDRATION];
  if (!hydrationInfo) {
    return;
  }
  if (!isI18nHydrationSupportEnabled() || parentTNode && (isI18nInSkipHydrationBlock(parentTNode) || isDisconnectedNode$1(hydrationInfo, parentTNode.index - HEADER_OFFSET))) {
    return;
  }
  const tView = lView[TVIEW$1];
  const tI18n = tView.data[index];
  ngDevMode && assertDefined(tI18n, 'Expected i18n data to be present in a given TView slot during hydration');
  function findHydrationRoot() {
    if (isRootTemplateMessage(subTemplateIndex)) {
      ngDevMode && assertDefined(parentTNode, 'Expected parent TNode while hydrating i18n root');
      const rootNode = locateNextRNode(hydrationInfo, tView, lView, parentTNode);
      return parentTNode.type & 8 ? rootNode : rootNode.firstChild;
    }
    return hydrationInfo?.firstChild;
  }
  const currentNode = findHydrationRoot();
  ngDevMode && assertDefined(currentNode, 'Expected root i18n node during hydration');
  const disconnectedNodes = initDisconnectedNodes(hydrationInfo) ?? new Set();
  const i18nNodes = hydrationInfo.i18nNodes ??= new Map();
  const caseQueue = hydrationInfo.data[I18N_DATA]?.[index - HEADER_OFFSET] ?? [];
  const dehydratedIcuData = hydrationInfo.dehydratedIcuData ??= new Map();
  collectI18nNodesFromDom({
    hydrationInfo,
    lView,
    i18nNodes,
    disconnectedNodes,
    caseQueue,
    dehydratedIcuData
  }, {
    currentNode,
    isConnected: true
  }, tI18n.ast);
  hydrationInfo.disconnectedNodes = disconnectedNodes.size === 0 ? null : disconnectedNodes;
}
function collectI18nNodesFromDom(context, state, nodeOrNodes) {
  if (Array.isArray(nodeOrNodes)) {
    let nextState = state;
    for (const node of nodeOrNodes) {
      const targetNode = tryLocateRNodeByPath(context.hydrationInfo, context.lView, node.index - HEADER_OFFSET);
      if (targetNode) {
        nextState = forkHydrationState(state, targetNode);
      }
      collectI18nNodesFromDom(context, nextState, node);
    }
  } else {
    if (context.disconnectedNodes.has(nodeOrNodes.index - HEADER_OFFSET)) {
      return;
    }
    switch (nodeOrNodes.kind) {
      case 0:
        {
          const currentNode = appendI18nNodeToCollection(context, state, nodeOrNodes);
          setCurrentNode(state, currentNode?.nextSibling ?? null);
          break;
        }
      case 1:
        {
          collectI18nNodesFromDom(context, forkHydrationState(state, state.currentNode?.firstChild ?? null), nodeOrNodes.children);
          const currentNode = appendI18nNodeToCollection(context, state, nodeOrNodes);
          setCurrentNode(state, currentNode?.nextSibling ?? null);
          break;
        }
      case 2:
        {
          const noOffsetIndex = nodeOrNodes.index - HEADER_OFFSET;
          const {
            hydrationInfo
          } = context;
          const containerSize = getNgContainerSize(hydrationInfo, noOffsetIndex);
          switch (nodeOrNodes.type) {
            case 0:
              {
                const currentNode = appendI18nNodeToCollection(context, state, nodeOrNodes);
                if (isSerializedElementContainer(hydrationInfo, noOffsetIndex)) {
                  collectI18nNodesFromDom(context, state, nodeOrNodes.children);
                  const nextNode = skipSiblingNodes(state, 1);
                  setCurrentNode(state, nextNode);
                } else {
                  collectI18nNodesFromDom(context, forkHydrationState(state, state.currentNode?.firstChild ?? null), nodeOrNodes.children);
                  setCurrentNode(state, currentNode?.nextSibling ?? null);
                  if (containerSize !== null) {
                    const nextNode = skipSiblingNodes(state, containerSize + 1);
                    setCurrentNode(state, nextNode);
                  }
                }
                break;
              }
            case 1:
              {
                ngDevMode && assertNotEqual(containerSize, null, 'Expected a container size while hydrating i18n subtemplate');
                appendI18nNodeToCollection(context, state, nodeOrNodes);
                const nextNode = skipSiblingNodes(state, containerSize + 1);
                setCurrentNode(state, nextNode);
                break;
              }
          }
          break;
        }
      case 3:
        {
          const selectedCase = state.isConnected ? context.caseQueue.shift() : null;
          const childState = {
            currentNode: null,
            isConnected: false
          };
          for (let i = 0; i < nodeOrNodes.cases.length; i++) {
            collectI18nNodesFromDom(context, i === selectedCase ? state : childState, nodeOrNodes.cases[i]);
          }
          if (selectedCase !== null) {
            context.dehydratedIcuData.set(nodeOrNodes.index, {
              case: selectedCase,
              node: nodeOrNodes
            });
          }
          const currentNode = appendI18nNodeToCollection(context, state, nodeOrNodes);
          setCurrentNode(state, currentNode?.nextSibling ?? null);
          break;
        }
    }
  }
}
let _claimDehydratedIcuCaseImpl = () => {};
function claimDehydratedIcuCase(lView, icuIndex, caseIndex) {
  _claimDehydratedIcuCaseImpl(lView, icuIndex, caseIndex);
}
function enableClaimDehydratedIcuCaseImpl() {
  _claimDehydratedIcuCaseImpl = claimDehydratedIcuCaseImpl;
}
function claimDehydratedIcuCaseImpl(lView, icuIndex, caseIndex) {
  const dehydratedIcuDataMap = lView[HYDRATION]?.dehydratedIcuData;
  if (dehydratedIcuDataMap) {
    const dehydratedIcuData = dehydratedIcuDataMap.get(icuIndex);
    if (dehydratedIcuData?.case === caseIndex) {
      dehydratedIcuDataMap.delete(icuIndex);
    }
  }
}
function cleanupI18nHydrationData(lView) {
  const hydrationInfo = lView[HYDRATION];
  if (hydrationInfo) {
    const {
      i18nNodes,
      dehydratedIcuData: dehydratedIcuDataMap
    } = hydrationInfo;
    if (i18nNodes && dehydratedIcuDataMap) {
      const renderer = lView[RENDERER];
      for (const dehydratedIcuData of dehydratedIcuDataMap.values()) {
        cleanupDehydratedIcuData(renderer, i18nNodes, dehydratedIcuData);
      }
    }
    hydrationInfo.i18nNodes = undefined;
    hydrationInfo.dehydratedIcuData = undefined;
  }
}
function cleanupDehydratedIcuData(renderer, i18nNodes, dehydratedIcuData) {
  for (const node of dehydratedIcuData.node.cases[dehydratedIcuData.case]) {
    const rNode = i18nNodes.get(node.index - HEADER_OFFSET);
    if (rNode) {
      nativeRemoveNode(renderer, rNode, false);
    }
  }
}

function removeDehydratedViews(lContainer) {
  const views = lContainer[DEHYDRATED_VIEWS] ?? [];
  const parentLView = lContainer[PARENT];
  const renderer = parentLView[RENDERER];
  const retainedViews = [];
  for (const view of views) {
    if (view.data[DEFER_BLOCK_ID] !== undefined) {
      retainedViews.push(view);
    } else {
      removeDehydratedView(view, renderer);
      ngDevMode && ngDevMode.dehydratedViewsRemoved++;
    }
  }
  lContainer[DEHYDRATED_VIEWS] = retainedViews;
}
function removeDehydratedViewList(deferBlock) {
  const {
    lContainer
  } = deferBlock;
  const dehydratedViews = lContainer[DEHYDRATED_VIEWS];
  if (dehydratedViews === null) return;
  const parentLView = lContainer[PARENT];
  const renderer = parentLView[RENDERER];
  for (const view of dehydratedViews) {
    removeDehydratedView(view, renderer);
    ngDevMode && ngDevMode.dehydratedViewsRemoved++;
  }
}
function removeDehydratedView(dehydratedView, renderer) {
  let nodesRemoved = 0;
  let currentRNode = dehydratedView.firstChild;
  if (currentRNode) {
    const numNodes = dehydratedView.data[NUM_ROOT_NODES];
    while (nodesRemoved < numNodes) {
      ngDevMode && validateSiblingNodeExists(currentRNode);
      const nextSibling = currentRNode.nextSibling;
      nativeRemoveNode(renderer, currentRNode, false);
      currentRNode = nextSibling;
      nodesRemoved++;
    }
  }
}
function cleanupLContainer(lContainer) {
  removeDehydratedViews(lContainer);
  const hostLView = lContainer[HOST];
  if (isLView(hostLView)) {
    cleanupLView(hostLView);
  }
  for (let i = CONTAINER_HEADER_OFFSET; i < lContainer.length; i++) {
    cleanupLView(lContainer[i]);
  }
}
function cleanupLView(lView) {
  cleanupI18nHydrationData(lView);
  const tView = lView[TVIEW$1];
  for (let i = HEADER_OFFSET; i < tView.bindingStartIndex; i++) {
    if (isLContainer(lView[i])) {
      const lContainer = lView[i];
      cleanupLContainer(lContainer);
    } else if (isLView(lView[i])) {
      cleanupLView(lView[i]);
    }
  }
}
function cleanupDehydratedViews(appRef) {
  const viewRefs = appRef._views;
  for (const viewRef of viewRefs) {
    const lNode = getLNodeForHydration(viewRef);
    if (lNode !== null && lNode[HOST] !== null) {
      if (isLView(lNode)) {
        cleanupLView(lNode);
      } else {
        cleanupLContainer(lNode);
      }
      ngDevMode && ngDevMode.dehydratedViewsCleanupRuns++;
    }
  }
}
function cleanupHydratedDeferBlocks(deferBlock, hydratedBlocks, registry, appRef) {
  if (deferBlock !== null) {
    registry.cleanup(hydratedBlocks);
    cleanupLContainer(deferBlock.lContainer);
    cleanupDehydratedViews(appRef);
  }
}

function locateDehydratedViewsInContainer(currentRNode, serializedViews) {
  const dehydratedViews = [];
  for (const serializedView of serializedViews) {
    for (let i = 0; i < (serializedView[MULTIPLIER] ?? 1); i++) {
      const view = {
        data: serializedView,
        firstChild: null
      };
      if (serializedView[NUM_ROOT_NODES] > 0) {
        view.firstChild = currentRNode;
        currentRNode = siblingAfter(serializedView[NUM_ROOT_NODES], currentRNode);
      }
      dehydratedViews.push(view);
    }
  }
  return [currentRNode, dehydratedViews];
}
let _findMatchingDehydratedViewImpl = () => null;
let _findAndReconcileMatchingDehydratedViewsImpl = () => null;
function enableFindMatchingDehydratedViewImpl() {
  _findMatchingDehydratedViewImpl = findMatchingDehydratedViewImpl;
  _findAndReconcileMatchingDehydratedViewsImpl = findAndReconcileMatchingDehydratedViewsImpl;
}
function findMatchingDehydratedViewImpl(lContainer, template) {
  if (hasMatchingDehydratedView(lContainer, template)) {
    return lContainer[DEHYDRATED_VIEWS].shift();
  } else {
    removeDehydratedViews(lContainer);
    return null;
  }
}
function findMatchingDehydratedView(lContainer, template) {
  return _findMatchingDehydratedViewImpl(lContainer, template);
}
function findAndReconcileMatchingDehydratedViewsImpl(lContainer, templateTNode, hostLView) {
  if (templateTNode.tView.ssrId === null) return null;
  const dehydratedView = findMatchingDehydratedView(lContainer, templateTNode.tView.ssrId);
  if (hostLView[TVIEW$1].firstUpdatePass && dehydratedView === null) {
    removeStaleDehydratedBranch(hostLView, templateTNode);
  }
  return dehydratedView;
}
function findAndReconcileMatchingDehydratedViews(lContainer, templateTNode, hostLView) {
  return _findAndReconcileMatchingDehydratedViewsImpl(lContainer, templateTNode, hostLView);
}
function removeStaleDehydratedBranch(hostLView, tNode) {
  let currentTNode = tNode;
  while (currentTNode) {
    if (cleanupMatchingDehydratedViews(hostLView, currentTNode)) return;
    if ((currentTNode.flags & 256) === 256) {
      break;
    }
    currentTNode = currentTNode.prev;
  }
  currentTNode = tNode.next;
  while (currentTNode) {
    if ((currentTNode.flags & 512) !== 512) {
      break;
    }
    if (cleanupMatchingDehydratedViews(hostLView, currentTNode)) return;
    currentTNode = currentTNode.next;
  }
}
function hasMatchingDehydratedView(lContainer, template) {
  const views = lContainer[DEHYDRATED_VIEWS];
  if (!template || views === null || views.length === 0) {
    return false;
  }
  return views[0].data[TEMPLATE_ID] === template;
}
function cleanupMatchingDehydratedViews(hostLView, currentTNode) {
  const ssrId = currentTNode.tView?.ssrId;
  if (ssrId == null) return false;
  const container = hostLView[currentTNode.index];
  if (isLContainer(container) && hasMatchingDehydratedView(container, ssrId)) {
    removeDehydratedViews(container);
    return true;
  }
  return false;
}

let ComponentRef$1 = class ComponentRef {};

class RendererFactory2 {}
class Renderer2 {
  destroyNode = null;
  static __NG_ELEMENT_ID__ = () => injectRenderer2();
}
if (typeof ngDevMode === 'undefined' || ngDevMode) {
  registerSpecialProvider(Renderer2);
}
function injectRenderer2() {
  const lView = getLView();
  const tNode = getCurrentTNode();
  const nodeAtIndex = getComponentLViewByIndex(tNode.index, lView);
  return (isLView(nodeAtIndex) ? nodeAtIndex : lView)[RENDERER];
}

class Sanitizer {
  static ɵprov =
  /* @__PURE__ */
  __defineInjectable({
    token: Sanitizer,
    providedIn: 'root',
    factory: () => null
  });
}

const RENDER = Symbol('RENDER');
const ON_DESTROY = Symbol('ON_DESTROY');
const CONTENT_ADAPTER = Symbol('CONTENT_ADAPTER');
const GET_CONTEXT = Symbol('GET_CONTEXT');

function isForeignComponent(value) {
  return typeof value === 'object' && value !== null && RENDER in value;
}
function isModuleWithProviders(value) {
  return value.ngModule !== undefined;
}
function isNgModule(value) {
  return !!getNgModuleDef(value);
}
function isPipe(value) {
  return !!getPipeDef$1(value);
}
function isDirective(value) {
  return !!getDirectiveDef(value);
}
function isComponent(value) {
  return !!getComponentDef(value);
}
function getDependencyTypeForError(type) {
  if (getComponentDef(type)) return 'component';
  if (getDirectiveDef(type)) return 'directive';
  if (getPipeDef$1(type)) return 'pipe';
  return 'type';
}
function verifyStandaloneImport(depType, importingType) {
  if (isForwardRef(depType)) {
    depType = resolveForwardRef(depType);
    if (!depType) {
      throw new Error(`Expected forwardRef function, imported from "${stringifyForError(importingType)}", to return a standalone entity or NgModule but got "${stringifyForError(depType) || depType}".`);
    }
  }
  if (getNgModuleDef(depType) == null) {
    const def = getComponentDef(depType) || getDirectiveDef(depType) || getPipeDef$1(depType);
    if (def != null) {
      if (!def.standalone) {
        const type = getDependencyTypeForError(depType);
        throw new Error(`The "${stringifyForError(depType)}" ${type}, imported from "${stringifyForError(importingType)}", is not standalone. Does the ${type} have the standalone: false flag?`);
      }
    } else {
      if (isModuleWithProviders(depType)) {
        throw new Error(`A module with providers was imported from "${stringifyForError(importingType)}". Modules with providers are not supported in standalone components imports.`);
      } else if (isForeignComponent(depType)) {
        throw new Error(`A foreign component, imported from "${stringifyForError(importingType)}", cannot be imported using 'imports'. Foreign components are only supported in AOT mode and must be registered in 'foreignImports'.`);
      } else {
        throw new Error(`The "${stringifyForError(depType)}" type, imported from "${stringifyForError(importingType)}", must be a standalone component / directive / pipe or an NgModule. Did you forget to add the required @Component / @Directive / @Pipe or @NgModule annotation?`);
      }
    }
  }
}

class DepsTracker {
  ownerNgModule = new WeakMap();
  ngModulesWithSomeUnresolvedDecls = new Set();
  ngModulesScopeCache = new WeakMap();
  standaloneComponentsScopeCache = new WeakMap();
  resolveNgModulesDecls() {
    if (this.ngModulesWithSomeUnresolvedDecls.size === 0) {
      return;
    }
    for (const moduleType of this.ngModulesWithSomeUnresolvedDecls) {
      const def = getNgModuleDef(moduleType);
      if (def?.declarations) {
        for (const decl of maybeUnwrapFn(def.declarations)) {
          if (isComponent(decl)) {
            this.ownerNgModule.set(decl, moduleType);
          }
        }
      }
    }
    this.ngModulesWithSomeUnresolvedDecls.clear();
  }
  getComponentDependencies(type, rawImports) {
    this.resolveNgModulesDecls();
    const def = getComponentDef(type);
    if (def === null) {
      throw new Error(`Attempting to get component dependencies for a type that is not a component: ${type}`);
    }
    if (def.standalone) {
      const scope = this.getStandaloneComponentScope(type, rawImports);
      if (scope.compilation.isPoisoned) {
        return {
          dependencies: []
        };
      }
      return {
        dependencies: [...scope.compilation.directives, ...scope.compilation.pipes, ...scope.compilation.ngModules]
      };
    } else {
      if (!this.ownerNgModule.has(type)) {
        return {
          dependencies: []
        };
      }
      const scope = this.getNgModuleScope(this.ownerNgModule.get(type));
      if (scope.compilation.isPoisoned) {
        return {
          dependencies: []
        };
      }
      return {
        dependencies: [...scope.compilation.directives, ...scope.compilation.pipes]
      };
    }
  }
  registerNgModule(type, scopeInfo) {
    if (!isNgModule(type)) {
      throw new Error(`Attempting to register a Type which is not NgModule as NgModule: ${type}`);
    }
    this.ngModulesWithSomeUnresolvedDecls.add(type);
  }
  clearScopeCacheFor(type) {
    this.ngModulesScopeCache.delete(type);
    this.standaloneComponentsScopeCache.delete(type);
  }
  getNgModuleScope(type) {
    if (this.ngModulesScopeCache.has(type)) {
      return this.ngModulesScopeCache.get(type);
    }
    const scope = this.computeNgModuleScope(type);
    this.ngModulesScopeCache.set(type, scope);
    return scope;
  }
  computeNgModuleScope(type) {
    const def = getNgModuleDefOrThrow(type);
    const scope = {
      exported: {
        directives: new Set(),
        pipes: new Set()
      },
      compilation: {
        directives: new Set(),
        pipes: new Set()
      }
    };
    for (const imported of maybeUnwrapFn(def.imports)) {
      if (isNgModule(imported)) {
        const importedScope = this.getNgModuleScope(imported);
        addSet(importedScope.exported.directives, scope.compilation.directives);
        addSet(importedScope.exported.pipes, scope.compilation.pipes);
      } else if (isStandalone(imported)) {
        if (isDirective(imported) || isComponent(imported)) {
          scope.compilation.directives.add(imported);
        } else if (isPipe(imported)) {
          scope.compilation.pipes.add(imported);
        } else {
          throw new RuntimeError(980, 'The standalone imported type is neither a component nor a directive nor a pipe');
        }
      } else {
        scope.compilation.isPoisoned = true;
        break;
      }
    }
    if (!scope.compilation.isPoisoned) {
      for (const decl of maybeUnwrapFn(def.declarations)) {
        if (isNgModule(decl) || isStandalone(decl)) {
          scope.compilation.isPoisoned = true;
          break;
        }
        if (isPipe(decl)) {
          scope.compilation.pipes.add(decl);
        } else {
          scope.compilation.directives.add(decl);
        }
      }
    }
    for (const exported of maybeUnwrapFn(def.exports)) {
      if (isNgModule(exported)) {
        const exportedScope = this.getNgModuleScope(exported);
        addSet(exportedScope.exported.directives, scope.exported.directives);
        addSet(exportedScope.exported.pipes, scope.exported.pipes);
        addSet(exportedScope.exported.directives, scope.compilation.directives);
        addSet(exportedScope.exported.pipes, scope.compilation.pipes);
      } else if (isPipe(exported)) {
        scope.exported.pipes.add(exported);
      } else {
        scope.exported.directives.add(exported);
      }
    }
    return scope;
  }
  getStandaloneComponentScope(type, rawImports) {
    if (this.standaloneComponentsScopeCache.has(type)) {
      return this.standaloneComponentsScopeCache.get(type);
    }
    const ans = this.computeStandaloneComponentScope(type, rawImports);
    this.standaloneComponentsScopeCache.set(type, ans);
    return ans;
  }
  computeStandaloneComponentScope(type, rawImports) {
    const ans = {
      compilation: {
        directives: new Set([type]),
        pipes: new Set(),
        ngModules: new Set()
      }
    };
    for (const rawImport of flatten(rawImports ?? [])) {
      const imported = resolveForwardRef(rawImport);
      if (imported && isNgModule(imported)) {
        ans.compilation.ngModules.add(imported);
        const importedScope = this.getNgModuleScope(imported);
        if (importedScope.exported.isPoisoned) {
          ans.compilation.isPoisoned = true;
          return ans;
        }
        addSet(importedScope.exported.directives, ans.compilation.directives);
        addSet(importedScope.exported.pipes, ans.compilation.pipes);
      } else if (imported && isStandalone(imported)) {
        if (isPipe(imported)) {
          ans.compilation.pipes.add(imported);
        } else if (isDirective(imported) || isComponent(imported)) {
          ans.compilation.directives.add(imported);
        } else {
          ans.compilation.isPoisoned = true;
          return ans;
        }
      } else {
        ans.compilation.isPoisoned = true;
        return ans;
      }
    }
    return ans;
  }
  isOrphanComponent(cmp) {
    const def = getComponentDef(cmp);
    if (!def || def.standalone) {
      return false;
    }
    this.resolveNgModulesDecls();
    return !this.ownerNgModule.has(cmp);
  }
}
function addSet(sourceSet, targetSet) {
  for (const m of sourceSet) {
    targetSet.add(m);
  }
}
const depsTracker = new DepsTracker();

function getClosestComponentName(node, predicate) {
  let currentNode = node;
  while (currentNode) {
    const lView = readPatchedLView(currentNode);
    if (lView !== null) {
      for (let i = HEADER_OFFSET; i < lView.length; i++) {
        const current = lView[i];
        if (!isLView(current) && !isLContainer(current) || current[HOST] !== currentNode) {
          continue;
        }
        const tView = lView[TVIEW$1];
        const tNode = getTNode(tView, i);
        if (isComponentHost(tNode)) {
          const def = tView.data[tNode.directiveStart + tNode.componentOffset];
          const name = getComponentName(def);
          if (name !== null && (!predicate || predicate(currentNode, name))) {
            return name;
          } else {
            break;
          }
        }
      }
    }
    currentNode = currentNode.parentNode;
  }
  return null;
}
function getComponentName(def) {
  return def.debugInfo?.className || def.type.name || null;
}

const NOT_FOUND_CHECK_ONLY_ELEMENT_INJECTOR = {};

class ChainedInjector {
  injector;
  parentInjector;
  constructor(injector, parentInjector) {
    this.injector = injector;
    this.parentInjector = parentInjector;
  }
  get(token, notFoundValue, options) {
    const value = this.injector.get(token, NOT_FOUND_CHECK_ONLY_ELEMENT_INJECTOR, options);
    if (value !== NOT_FOUND_CHECK_ONLY_ELEMENT_INJECTOR || notFoundValue === NOT_FOUND_CHECK_ONLY_ELEMENT_INJECTOR) {
      return value;
    }
    return this.parentInjector.get(token, notFoundValue, options);
  }
}

function isListLikeIterable(obj) {
  if (!isJsObject(obj)) return false;
  return Array.isArray(obj) || !(obj instanceof Map) && Symbol.iterator in obj;
}
function areIterablesEqual(a, b, comparator) {
  const iterator1 = a[Symbol.iterator]();
  const iterator2 = b[Symbol.iterator]();
  while (true) {
    const item1 = iterator1.next();
    const item2 = iterator2.next();
    if (item1.done && item2.done) return true;
    if (item1.done || item2.done) return false;
    if (!comparator(item1.value, item2.value)) return false;
  }
}
function iterateListLike(obj, fn) {
  if (Array.isArray(obj)) {
    for (let i = 0; i < obj.length; i++) {
      fn(obj[i]);
    }
  } else {
    const iterator = obj[Symbol.iterator]();
    let item;
    while (!(item = iterator.next()).done) {
      fn(item.value);
    }
  }
}
function isJsObject(o) {
  return o !== null && (typeof o === 'function' || typeof o === 'object');
}

function devModeEqual(a, b) {
  const isListLikeIterableA = isListLikeIterable(a);
  const isListLikeIterableB = isListLikeIterable(b);
  if (isListLikeIterableA && isListLikeIterableB) {
    return areIterablesEqual(a, b, devModeEqual);
  } else {
    const isAObject = a && (typeof a === 'object' || typeof a === 'function');
    const isBObject = b && (typeof b === 'object' || typeof b === 'function');
    if (!isListLikeIterableA && isAObject && !isListLikeIterableB && isBObject) {
      return true;
    } else {
      return Object.is(a, b);
    }
  }
}

function updateBinding(lView, bindingIndex, value) {
  return lView[bindingIndex] = value;
}
function getBinding(lView, bindingIndex) {
  ngDevMode && assertIndexInRange(lView, bindingIndex);
  ngDevMode && assertNotSame(lView[bindingIndex], NO_CHANGE, 'Stored value should never be NO_CHANGE.');
  return lView[bindingIndex];
}
function bindingUpdated(lView, bindingIndex, value) {
  ngDevMode && assertLessThan(bindingIndex, lView.length, `Slot should have been initialized to NO_CHANGE`);
  if (value === NO_CHANGE) {
    return false;
  }
  const oldValue = lView[bindingIndex];
  if (Object.is(oldValue, value)) {
    return false;
  } else {
    if (ngDevMode && isInCheckNoChangesMode()) {
      const oldValueToCompare = oldValue !== NO_CHANGE ? oldValue : undefined;
      if (!devModeEqual(oldValueToCompare, value)) {
        const details = getExpressionChangedErrorDetails(lView, bindingIndex, oldValueToCompare, value);
        throwErrorIfNoChangesMode(oldValue === NO_CHANGE, details.oldValue, details.newValue, details.propName, lView);
      }
      return false;
    }
    lView[bindingIndex] = value;
    return true;
  }
}
function bindingUpdated2(lView, bindingIndex, exp1, exp2) {
  const different = bindingUpdated(lView, bindingIndex, exp1);
  return bindingUpdated(lView, bindingIndex + 1, exp2) || different;
}
function bindingUpdated3(lView, bindingIndex, exp1, exp2, exp3) {
  const different = bindingUpdated2(lView, bindingIndex, exp1, exp2);
  return bindingUpdated(lView, bindingIndex + 2, exp3) || different;
}
function bindingUpdated4(lView, bindingIndex, exp1, exp2, exp3, exp4) {
  const different = bindingUpdated2(lView, bindingIndex, exp1, exp2);
  return bindingUpdated2(lView, bindingIndex + 2, exp3, exp4) || different;
}

function wrapListener(tNode, lView, listenerFn) {
  return function wrapListenerIn_markDirtyAndPreventDefault(event) {
    const nativeEl = wrapListenerIn_markDirtyAndPreventDefault.__ngNativeEl__;
    if (nativeEl !== undefined) {
      markEventHandledForElement(event, nativeEl);
    }
    const startView = isComponentHost(tNode) ? getComponentLViewByIndex(tNode.index, lView) : lView;
    markViewDirty(startView, 5);
    const context = lView[CONTEXT];
    let result = executeListenerWithErrorHandling(lView, context, listenerFn, event);
    let nextListenerFn = wrapListenerIn_markDirtyAndPreventDefault.__ngNextListenerFn__;
    while (nextListenerFn) {
      result = executeListenerWithErrorHandling(lView, context, nextListenerFn, event) && result;
      nextListenerFn = nextListenerFn.__ngNextListenerFn__;
    }
    return result;
  };
}
function executeListenerWithErrorHandling(lView, context, listenerFn, e) {
  const prevConsumer = setActiveConsumer$1(null);
  try {
    profiler(ProfilerEvent.OutputStart, context, listenerFn);
    return listenerFn(e) !== false;
  } catch (error) {
    handleUncaughtError(lView, error);
    return false;
  } finally {
    profiler(ProfilerEvent.OutputEnd, context, listenerFn);
    setActiveConsumer$1(prevConsumer);
  }
}
function listenToDomEvent(tNode, tView, lView, eventTargetResolver, renderer, eventName, originalListener, wrappedListener) {
  ngDevMode && assertNotSame(wrappedListener, originalListener, 'Expected wrapped and original listeners to be different.');
  const isTNodeDirectiveHost = isDirectiveHost(tNode);
  let hasCoalesced = false;
  let existingListener = null;
  if (!eventTargetResolver && isTNodeDirectiveHost) {
    existingListener = findExistingListener(tView, lView, eventName, tNode.index);
  }
  if (existingListener !== null) {
    const lastListenerFn = existingListener.__ngLastListenerFn__ || existingListener;
    lastListenerFn.__ngNextListenerFn__ = originalListener;
    existingListener.__ngLastListenerFn__ = originalListener;
    hasCoalesced = true;
  } else {
    const native = getNativeByTNode(tNode, lView);
    const target = eventTargetResolver ? eventTargetResolver(native) : native;
    stashEventListenerImpl(lView, target, eventName, wrappedListener);
    if (!eventTargetResolver) {
      wrappedListener.__ngNativeEl__ = native;
    }
    const cleanupFn = renderer.listen(target, eventName, wrappedListener);
    if (!isAnimationEventType(eventName)) {
      const idxOrTargetGetter = eventTargetResolver ? _lView => eventTargetResolver(unwrapRNode(_lView[tNode.index])) : tNode.index;
      storeListenerCleanup(idxOrTargetGetter, tView, lView, eventName, wrappedListener, cleanupFn, false);
    }
  }
  return hasCoalesced;
}
function isAnimationEventType(eventName) {
  return eventName.startsWith('animation') || eventName.startsWith('transition');
}
function findExistingListener(tView, lView, eventName, tNodeIndex) {
  const tCleanup = tView.cleanup;
  if (tCleanup != null) {
    for (let i = 0; i < tCleanup.length - 1; i += 2) {
      const cleanupEventName = tCleanup[i];
      if (cleanupEventName === eventName && tCleanup[i + 1] === tNodeIndex) {
        const lCleanup = lView[CLEANUP];
        const listenerIdxInLCleanup = tCleanup[i + 2];
        return lCleanup && lCleanup.length > listenerIdxInLCleanup ? lCleanup[listenerIdxInLCleanup] : null;
      }
      if (typeof cleanupEventName === 'string') {
        i += 2;
      }
    }
  }
  return null;
}
function storeListenerCleanup(indexOrTargetGetter, tView, lView, eventName, listenerFn, cleanup, isOutput) {
  const tCleanup = tView.firstCreatePass ? getOrCreateTViewCleanup(tView) : null;
  const lCleanup = getOrCreateLViewCleanup(lView);
  const index = lCleanup.length;
  lCleanup.push(listenerFn, cleanup);
  tCleanup && tCleanup.push(eventName, indexOrTargetGetter, index, (index + 1) * (isOutput ? -1 : 1));
}

function createOutputListener(tNode, lView, listenerFn, targetDef, eventName) {
  const wrappedListener = wrapListener(tNode, lView, listenerFn);
  const hasBound = listenToDirectiveOutput(tNode, lView, targetDef, eventName, wrappedListener);
  if (!hasBound && ngDevMode) {
    throw new RuntimeError(316, `${stringifyForError(targetDef.type)} does not have an output with a public name of "${eventName}".`);
  }
}
function listenToDirectiveOutput(tNode, lView, target, eventName, listenerFn) {
  let hostIndex = null;
  let hostDirectivesStart = null;
  let hostDirectivesEnd = null;
  let hasOutput = false;
  if (ngDevMode && !tNode.directiveToIndex?.has(target.type)) {
    throw new Error(`Node does not have a directive with type ${target.type.name}`);
  }
  const data = tNode.directiveToIndex.get(target.type);
  if (typeof data === 'number') {
    hostIndex = data;
  } else {
    [hostIndex, hostDirectivesStart, hostDirectivesEnd] = data;
  }
  if (hostDirectivesStart !== null && hostDirectivesEnd !== null && tNode.hostDirectiveOutputs && Object.hasOwn(tNode.hostDirectiveOutputs, eventName)) {
    const hostDirectiveOutputs = tNode.hostDirectiveOutputs[eventName];
    for (let i = 0; i < hostDirectiveOutputs.length; i += 2) {
      const index = hostDirectiveOutputs[i];
      if (index >= hostDirectivesStart && index <= hostDirectivesEnd) {
        ngDevMode && assertIndexInRange(lView, index);
        hasOutput = true;
        listenToOutput(tNode, lView, index, hostDirectiveOutputs[i + 1], eventName, listenerFn);
      } else if (index > hostDirectivesEnd) {
        break;
      }
    }
  }
  if (Object.hasOwn(target.outputs, eventName)) {
    ngDevMode && assertIndexInRange(lView, hostIndex);
    hasOutput = true;
    listenToOutput(tNode, lView, hostIndex, eventName, eventName, listenerFn);
  }
  return hasOutput;
}
function listenToOutput(tNode, lView, directiveIndex, lookupName, eventName, listenerFn) {
  ngDevMode && assertIndexInRange(lView, directiveIndex);
  const instance = lView[directiveIndex];
  const tView = lView[TVIEW$1];
  const def = tView.data[directiveIndex];
  const propertyName = def.outputs[lookupName];
  const output = instance[propertyName];
  if (ngDevMode && !isOutputSubscribable(output)) {
    throw new Error(`@Output ${propertyName} not initialized in '${instance.constructor.name}'.`);
  }
  const subscription = output.subscribe(listenerFn);
  storeListenerCleanup(tNode.index, tView, lView, eventName, listenerFn, subscription, true);
}
function isOutputSubscribable(value) {
  return value != null && typeof value.subscribe === 'function';
}

function ɵɵcontrolCreate() {
  controlCreateInternal();
}
function controlCreateInternal() {
  const lView = getLView();
  const tView = getTView();
  const tNode = getCurrentTNode();
  if (tView.firstCreatePass) {
    initializeControlFirstCreatePass(tView, tNode);
  }
  if (tNode.controlDirectiveIndex === -1) {
    return;
  }
  performanceMarkFeature('NgSignalForms');
  const instance = lView[tNode.controlDirectiveIndex];
  const controlDef = tView.data[tNode.controlDirectiveIndex].controlDef;
  controlDef.create(instance, new ControlDirectiveHostImpl(lView, tView, tNode));
}
function ɵɵcontrol() {
  controlUpdateInternal();
}
function controlUpdateInternal() {
  if (ngDevMode && isInCheckNoChangesMode()) {
    return;
  }
  const lView = getLView();
  const tView = getTView();
  const tNode = getSelectedTNode();
  if (tNode.controlDirectiveIndex === -1) {
    return;
  }
  const controlDef = tView.data[tNode.controlDirectiveIndex].controlDef;
  const instance = lView[tNode.controlDirectiveIndex];
  controlDef.update(instance, new ControlDirectiveHostImpl(lView, tView, tNode));
}
class ControlDirectiveHostImpl {
  lView;
  tView;
  tNode;
  hasPassThrough;
  constructor(lView, tView, tNode) {
    this.lView = lView;
    this.tView = tView;
    this.tNode = tNode;
    this.hasPassThrough = !!(tNode.flags & 4096);
  }
  get customControl() {
    return this.tNode.customControlIndex !== -1 ? this.lView[this.tNode.customControlIndex] : undefined;
  }
  get nativeElement() {
    return getNativeByTNode(this.tNode, this.lView);
  }
  get descriptor() {
    if (ngDevMode && isComponentHost(this.tNode)) {
      const componentIndex = this.tNode.directiveStart + this.tNode.componentOffset;
      const componentDef = this.tView.data[componentIndex];
      return `Component ${debugStringifyTypeForError(componentDef.type)}`;
    }
    return `<${this.tNode.value}>`;
  }
  listenToCustomControlOutput(outputName, callback) {
    const directiveDef = this.tView.data[this.tNode.customControlIndex];
    listenToDirectiveOutput(this.tNode, this.lView, directiveDef, outputName, wrapListener(this.tNode, this.lView, callback));
  }
  listenToCustomControlModel(listener) {
    const modelName = this.tNode.flags & 1024 ? 'valueChange' : 'checkedChange';
    const directiveDef = this.tView.data[this.tNode.customControlIndex];
    listenToDirectiveOutput(this.tNode, this.lView, directiveDef, modelName, wrapListener(this.tNode, this.lView, listener));
  }
  setInputOnDirectives(inputName, value, writePredicate) {
    const directiveIndices = this.tNode.inputs?.[inputName];
    const hostDirectiveInputs = this.tNode.hostDirectiveInputs?.[inputName];
    if (!directiveIndices && !hostDirectiveInputs) {
      return false;
    }
    let wasSet = false;
    if (directiveIndices) {
      for (const index of directiveIndices) {
        if (index === this.tNode.controlDirectiveIndex) {
          continue;
        }
        const directive = this.lView[index];
        const directiveDef = this.tView.data[index];
        const matchesPredicate = !writePredicate || writePredicate(readInputFromDirective(directive, directiveDef, inputName));
        if (matchesPredicate) {
          writeToDirectiveInput(directiveDef, directive, inputName, value);
          wasSet = true;
        }
      }
    }
    if (hostDirectiveInputs) {
      for (let i = 0; i < hostDirectiveInputs.length; i += 2) {
        const index = hostDirectiveInputs[i];
        if (index === this.tNode.controlDirectiveIndex) {
          continue;
        }
        const directive = this.lView[index];
        const internalName = hostDirectiveInputs[i + 1];
        const directiveDef = this.tView.data[index];
        const matchesPredicate = !writePredicate || writePredicate(readInputFromDirective(directive, directiveDef, inputName));
        if (matchesPredicate) {
          writeToDirectiveInput(directiveDef, directive, internalName, value);
          wasSet = true;
        }
      }
    }
    return wasSet;
  }
  setCustomControlModelInput(value) {
    const directiveDef = this.tView.data[this.tNode.customControlIndex];
    const modelName = this.tNode.flags & 1024 ? 'value' : 'checked';
    setDirectiveInput(this.tNode, this.tView, this.lView, directiveDef, modelName, value);
  }
  customControlHasInput(inputName) {
    if (this.tNode.customControlIndex === -1) {
      return false;
    }
    const directiveDef = this.tView.data[this.tNode.customControlIndex];
    const presence = directiveDef.signalFormsInputPresence ??= this._buildCustomControlInputCache(directiveDef);
    return presence[inputName] === true;
  }
  _buildCustomControlInputCache(directiveDef) {
    const cache = {};
    for (const key in directiveDef.inputs) {
      cache[key] = true;
    }
    if (directiveDef.hostDirectives !== null) {
      const queue = [...directiveDef.hostDirectives];
      while (queue.length > 0) {
        const hostDir = queue.shift();
        if (typeof hostDir !== 'function') {
          for (const key in hostDir.inputs) {
            cache[hostDir.inputs[key]] = true;
          }
          const hostDirectives = getHostDirectives(hostDir.directive);
          if (hostDirectives !== null) {
            queue.push(...hostDirectives);
          }
          continue;
        }
        for (const config of hostDir()) {
          if (typeof config === 'function') {
            continue;
          }
          if (config.inputs) {
            for (let i = 0; i < config.inputs.length; i += 2) {
              const exposedName = config.inputs[i + 1] || config.inputs[i];
              cache[exposedName] = true;
            }
          }
          const hostDirectives = getHostDirectives(config.directive);
          if (hostDirectives !== null) {
            queue.push(...hostDirectives);
          }
        }
      }
    }
    return cache;
  }
}
function getHostDirectives(directiveType) {
  if (typeof directiveType === 'function' && 'ɵdir' in directiveType) {
    return directiveType.ɵdir.hostDirectives ?? null;
  }
  return null;
}
function readInputFromDirective(instance, directiveDef, inputName) {
  if (!directiveDef.inputs || !Object.hasOwn(directiveDef.inputs, inputName)) {
    return undefined;
  }
  const [privateName, flags] = directiveDef.inputs[inputName];
  if ((flags & InputFlags.SignalBased) !== 0) {
    const field = instance[privateName];
    const node = field[SIGNAL];
    return node.value === REQUIRED_UNSET_VALUE ? undefined : node.value;
  }
  return instance[privateName];
}
function initializeControlFirstCreatePass(tView, tNode, lView) {
  ngDevMode && assertFirstCreatePass(tView);
  for (let i = tNode.directiveStart; i < tNode.directiveEnd; i++) {
    const directiveDef = tView.data[i];
    if (directiveDef.controlDef) {
      tNode.controlDirectiveIndex = i;
      break;
    }
  }
  if (tNode.controlDirectiveIndex === -1) {
    return;
  }
  const controlDef = tView.data[tNode.controlDirectiveIndex].controlDef;
  if (controlDef.passThroughInput) {
    if ((tNode.inputs?.[controlDef.passThroughInput]?.length ?? 0) > 1) {
      tNode.flags |= 4096;
      return;
    }
  }
  initializeCustomControlStatus(tView, tNode);
}
function initializeCustomControlStatus(tView, tNode) {
  for (let i = tNode.directiveStart; i < tNode.directiveEnd; i++) {
    const directiveDef = tView.data[i];
    if (tNode.directiveToIndex && !tNode.directiveToIndex.has(directiveDef.type)) {
      continue;
    }
    if (hasModelInput(directiveDef, 'value')) {
      tNode.flags |= 1024;
      tNode.customControlIndex = i;
      return;
    }
    if (hasModelInput(directiveDef, 'checked')) {
      tNode.flags |= 2048;
      tNode.customControlIndex = i;
      return;
    }
  }
  if (tNode.hostDirectiveInputs !== null && tNode.hostDirectiveOutputs !== null && tNode.directiveToIndex !== null) {
    const checkModel = (modelName, flag) => {
      const inputs = tNode.hostDirectiveInputs[modelName];
      const outputs = tNode.hostDirectiveOutputs[modelName + 'Change'];
      if (!inputs || !outputs) {
        return false;
      }
      for (let i = 0; i < inputs.length; i += 2) {
        const inputIndex = inputs[i];
        for (let j = 0; j < outputs.length; j += 2) {
          const outputIndex = outputs[j];
          if (inputIndex !== outputIndex) {
            continue;
          }
          for (const data of tNode.directiveToIndex.values()) {
            if (!Array.isArray(data)) {
              continue;
            }
            const [hostIndex, start, end] = data;
            if (inputIndex >= start && inputIndex <= end) {
              tNode.flags |= flag;
              tNode.customControlIndex = hostIndex;
              return true;
            }
          }
        }
      }
      return false;
    };
    if (checkModel('value', 1024)) {
      return;
    }
    if (checkModel('checked', 2048)) {
      return;
    }
  }
}
function hasModelInput(directiveDef, name) {
  return hasInput(directiveDef, name) && hasOutput(directiveDef, name + 'Change');
}
function hasInput(directiveDef, name) {
  return name in directiveDef.inputs;
}
function hasOutput(directiveDef, name) {
  return name in directiveDef.outputs;
}

const BINDING = /* @__PURE__ */Symbol('BINDING');
const INPUT_BINDING_METADATA = {
  kind: 'input',
  requiredVars: 1
};
const OUTPUT_BINDING_METADATA = {
  kind: 'output',
  requiredVars: 0
};
function inputBindingUpdate(targetDirectiveIdx, publicName, value) {
  const lView = getLView();
  const bindingIndex = nextBindingIndex();
  if (bindingUpdated(lView, bindingIndex, value)) {
    const tView = lView[TVIEW$1];
    const tNode = getSelectedTNode();
    const componentLView = getComponentLViewByIndex(tNode.index, lView);
    markViewDirty(componentLView, 1);
    const targetDef = tView.directiveRegistry[targetDirectiveIdx];
    if (ngDevMode && !targetDef) {
      throw new RuntimeError(315, `Input binding to property "${publicName}" does not have a target.`);
    }
    const hasSet = setDirectiveInput(tNode, tView, lView, targetDef, publicName, value);
    if (ngDevMode) {
      if (!hasSet) {
        throw new RuntimeError(315, `${stringifyForError(targetDef.type)} does not have an input with a public name of "${publicName}".`);
      }
      storePropertyBindingMetadata(tView.data, tNode, publicName, bindingIndex);
    }
  }
}
function inputBinding(publicName, value) {
  if (publicName === 'formField') {
    const binding = {
      [BINDING]: INPUT_BINDING_METADATA,
      create: () => {
        controlCreateInternal();
      },
      update: () => {
        inputBindingUpdate(binding.targetIdx, publicName, value());
        controlUpdateInternal();
      }
    };
    return binding;
  }
  const binding = {
    [BINDING]: INPUT_BINDING_METADATA,
    update: () => inputBindingUpdate(binding.targetIdx, publicName, value())
  };
  return binding;
}
function outputBinding(eventName, listener) {
  const binding = {
    [BINDING]: OUTPUT_BINDING_METADATA,
    create: () => {
      const lView = getLView();
      const tNode = getCurrentTNode();
      const tView = lView[TVIEW$1];
      const targetDef = tView.directiveRegistry[binding.targetIdx];
      createOutputListener(tNode, lView, listener, targetDef, eventName);
    }
  };
  return binding;
}
function twoWayBinding(publicName, value) {
  const input = inputBinding(publicName, value);
  const output = outputBinding(publicName + 'Change', eventValue => value.set(eventValue));
  ngDevMode && assertNotDefined(input.create, 'Unexpected `create` callback in inputBinding');
  ngDevMode && assertNotDefined(output.update, 'Unexpected `update` callback in outputBinding');
  const binding = {
    [BINDING]: {
      kind: 'twoWay',
      requiredVars: input[BINDING].requiredVars + output[BINDING].requiredVars
    },
    set targetIdx(idx) {
      input.targetIdx = idx;
      output.targetIdx = idx;
    },
    create: output.create,
    update: input.update
  };
  return binding;
}

const SHARED_STYLES_HOST = new InjectionToken(typeof ngDevMode !== 'undefined' && ngDevMode ? 'SHARED_STYLES_HOST' : '');

function computeStaticStyling(tNode, attrs, writeToHost) {
  ngDevMode && assertFirstCreatePass(getTView(), 'Expecting to be called in first template pass only');
  let styles = writeToHost ? tNode.styles : null;
  let classes = writeToHost ? tNode.classes : null;
  let mode = 0;
  if (attrs !== null) {
    for (let i = 0; i < attrs.length; i++) {
      const value = attrs[i];
      if (typeof value === 'number') {
        mode = value;
      } else if (mode == 1) {
        classes = concatStringsWithSpace(classes, value);
      } else if (mode == 2) {
        const style = value;
        const styleValue = attrs[++i];
        styles = concatStringsWithSpace(styles, style + ': ' + styleValue + ';');
      }
    }
  }
  writeToHost ? tNode.styles = styles : tNode.stylesWithoutHost = styles;
  writeToHost ? tNode.classes = classes : tNode.classesWithoutHost = classes;
}

function ɵɵdirectiveInject(token, flags = 0) {
  const lView = getLView();
  if (lView === null) {
    ngDevMode && assertInjectImplementationNotEqual(ɵɵdirectiveInject);
    return __inject(token, flags);
  }
  const tNode = getCurrentTNode();
  const value = getOrCreateInjectable(tNode, lView, resolveForwardRef(token), flags);
  ngDevMode && emitInjectEvent(token, value, flags);
  return value;
}
function ɵɵinvalidFactory() {
  const msg = ngDevMode ? `This constructor was not compatible with Dependency Injection.` : 'invalid';
  throw new Error(msg);
}

function resolveDirectives(tView, lView, tNode, localRefs, directiveMatcher) {
  ngDevMode && assertFirstCreatePass(tView);
  const exportsMap = localRefs === null ? null : {
    '': -1
  };
  const matchedDirectiveDefs = directiveMatcher(tView, tNode);
  if (matchedDirectiveDefs !== null) {
    let directiveDefs = matchedDirectiveDefs;
    let hostDirectiveDefs = null;
    let hostDirectiveRanges = null;
    for (const def of matchedDirectiveDefs) {
      if (def.resolveHostDirectives !== null) {
        [directiveDefs, hostDirectiveDefs, hostDirectiveRanges] = def.resolveHostDirectives(matchedDirectiveDefs);
        break;
      }
    }
    ngDevMode && assertNoDuplicateDirectives(directiveDefs);
    initializeDirectives(tView, lView, tNode, directiveDefs, exportsMap, hostDirectiveDefs, hostDirectiveRanges);
  }
  if (exportsMap !== null && localRefs !== null) {
    cacheMatchingLocalNames(tNode, localRefs, exportsMap);
  }
}
function cacheMatchingLocalNames(tNode, localRefs, exportsMap) {
  const localNames = tNode.localNames = [];
  for (let i = 0; i < localRefs.length; i += 2) {
    const index = exportsMap[localRefs[i + 1]];
    if (index == null) throw new RuntimeError(-301, ngDevMode && `Export of name '${localRefs[i + 1]}' not found!`);
    localNames.push(localRefs[i], index);
  }
}
function markAsComponentHost(tView, hostTNode, componentOffset) {
  ngDevMode && assertFirstCreatePass(tView);
  ngDevMode && assertGreaterThan(componentOffset, -1, 'componentOffset must be great than -1');
  hostTNode.componentOffset = componentOffset;
  (tView.components ??= []).push(hostTNode.index);
}
function initializeDirectives(tView, lView, tNode, directives, exportsMap, hostDirectiveDefs, hostDirectiveRanges) {
  ngDevMode && assertFirstCreatePass(tView);
  const directivesLength = directives.length;
  let componentDef = null;
  for (let i = 0; i < directivesLength; i++) {
    const def = directives[i];
    if (componentDef === null && isComponentDef(def)) {
      componentDef = def;
      markAsComponentHost(tView, tNode, i);
    }
    diPublicInInjector(getOrCreateNodeInjectorForNode(tNode, lView), tView, def.type);
  }
  initTNodeFlags(tNode, tView.data.length, directivesLength);
  if (componentDef?.viewProvidersResolver) {
    componentDef.viewProvidersResolver(componentDef);
  }
  for (let i = 0; i < directivesLength; i++) {
    const def = directives[i];
    if (def.providersResolver) {
      def.providersResolver(def);
    }
  }
  let preOrderHooksFound = false;
  let preOrderCheckHooksFound = false;
  let directiveIdx = allocExpando(tView, lView, directivesLength, null);
  ngDevMode && assertSame(directiveIdx, tNode.directiveStart, 'TNode.directiveStart should point to just allocated space');
  if (directivesLength > 0) {
    tNode.directiveToIndex = new Map();
  }
  for (let i = 0; i < directivesLength; i++) {
    const def = directives[i];
    tNode.mergedAttrs = mergeHostAttrs(tNode.mergedAttrs, def.hostAttrs);
    configureViewWithDirective(tView, tNode, lView, directiveIdx, def);
    saveNameToExportMap(directiveIdx, def, exportsMap);
    if (hostDirectiveRanges !== null && hostDirectiveRanges.has(def)) {
      const [start, end] = hostDirectiveRanges.get(def);
      tNode.directiveToIndex.set(def.type, [directiveIdx, start + tNode.directiveStart, end + tNode.directiveStart]);
    } else if (hostDirectiveDefs === null || !hostDirectiveDefs.has(def)) {
      tNode.directiveToIndex.set(def.type, directiveIdx);
    }
    if (def.contentQueries !== null) tNode.flags |= 4;
    if (def.hostBindings !== null || def.hostAttrs !== null || def.hostVars !== 0) tNode.flags |= 64;
    const lifeCycleHooks = def.type.prototype;
    if (!preOrderHooksFound && (lifeCycleHooks.ngOnChanges || lifeCycleHooks.ngOnInit || lifeCycleHooks.ngDoCheck)) {
      (tView.preOrderHooks ??= []).push(tNode.index);
      preOrderHooksFound = true;
    }
    if (!preOrderCheckHooksFound && (lifeCycleHooks.ngOnChanges || lifeCycleHooks.ngDoCheck)) {
      (tView.preOrderCheckHooks ??= []).push(tNode.index);
      preOrderCheckHooksFound = true;
    }
    directiveIdx++;
  }
  initializeInputAndOutputAliases(tView, tNode, hostDirectiveDefs);
}
function initializeInputAndOutputAliases(tView, tNode, hostDirectiveDefs) {
  ngDevMode && assertFirstCreatePass(tView);
  for (let index = tNode.directiveStart; index < tNode.directiveEnd; index++) {
    const directiveDef = tView.data[index];
    if (hostDirectiveDefs === null || !hostDirectiveDefs.has(directiveDef)) {
      setupSelectorMatchedInputsOrOutputs(0, tNode, directiveDef, index);
      setupSelectorMatchedInputsOrOutputs(1, tNode, directiveDef, index);
      setupInitialInputs(tNode, index, false);
    } else {
      const hostDirectiveDef = hostDirectiveDefs.get(directiveDef);
      setupHostDirectiveInputsOrOutputs(0, tNode, hostDirectiveDef, index);
      setupHostDirectiveInputsOrOutputs(1, tNode, hostDirectiveDef, index);
      setupInitialInputs(tNode, index, true);
    }
  }
}
function setupSelectorMatchedInputsOrOutputs(mode, tNode, def, directiveIndex) {
  const aliasMap = mode === 0 ? def.inputs : def.outputs;
  for (const publicName in aliasMap) {
    if (Object.hasOwn(aliasMap, publicName)) {
      let bindings;
      if (mode === 0) {
        bindings = tNode.inputs ??= {};
      } else {
        bindings = tNode.outputs ??= {};
      }
      bindings[publicName] ??= [];
      bindings[publicName].push(directiveIndex);
      setShadowStylingInputFlags(tNode, publicName);
    }
  }
}
function setupHostDirectiveInputsOrOutputs(mode, tNode, config, directiveIndex) {
  const aliasMap = mode === 0 ? config.inputs : config.outputs;
  for (const initialName in aliasMap) {
    if (Object.hasOwn(aliasMap, initialName)) {
      const publicName = aliasMap[initialName];
      let bindings;
      if (mode === 0) {
        bindings = tNode.hostDirectiveInputs ??= {};
      } else {
        bindings = tNode.hostDirectiveOutputs ??= {};
      }
      bindings[publicName] ??= [];
      bindings[publicName].push(directiveIndex, initialName);
      setShadowStylingInputFlags(tNode, publicName);
    }
  }
}
function setShadowStylingInputFlags(tNode, publicName) {
  if (publicName === 'class') {
    tNode.flags |= 8;
  } else if (publicName === 'style') {
    tNode.flags |= 16;
  }
}
function setupInitialInputs(tNode, directiveIndex, isHostDirective) {
  const {
    attrs,
    inputs,
    hostDirectiveInputs
  } = tNode;
  if (attrs === null || !isHostDirective && inputs === null || isHostDirective && hostDirectiveInputs === null || isInlineTemplate(tNode)) {
    tNode.initialInputs ??= [];
    tNode.initialInputs.push(null);
    return;
  }
  let inputsToStore = null;
  let i = 0;
  while (i < attrs.length) {
    const attrName = attrs[i];
    if (attrName === 0) {
      i += 4;
      continue;
    } else if (attrName === 5) {
      i += 2;
      continue;
    } else if (typeof attrName === 'number') {
      break;
    }
    if (!isHostDirective && Object.hasOwn(inputs, attrName)) {
      const inputConfig = inputs[attrName];
      for (const index of inputConfig) {
        if (index === directiveIndex) {
          inputsToStore ??= [];
          inputsToStore.push(attrName, attrs[i + 1]);
          break;
        }
      }
    } else if (isHostDirective && Object.hasOwn(hostDirectiveInputs, attrName)) {
      const config = hostDirectiveInputs[attrName];
      for (let j = 0; j < config.length; j += 2) {
        if (config[j] === directiveIndex) {
          inputsToStore ??= [];
          inputsToStore.push(config[j + 1], attrs[i + 1]);
          break;
        }
      }
    }
    i += 2;
  }
  tNode.initialInputs ??= [];
  tNode.initialInputs.push(inputsToStore);
}
function configureViewWithDirective(tView, tNode, lView, directiveIndex, def) {
  ngDevMode && assertGreaterThanOrEqual(directiveIndex, HEADER_OFFSET, 'Must be in Expando section');
  tView.data[directiveIndex] = def;
  const directiveFactory = def.factory || (def.factory = getFactoryDef(def.type, true));
  const nodeInjectorFactory = new NodeInjectorFactory(directiveFactory, isComponentDef(def), ɵɵdirectiveInject, ngDevMode ? def.type.name : null);
  tView.blueprint[directiveIndex] = nodeInjectorFactory;
  lView[directiveIndex] = nodeInjectorFactory;
  registerHostBindingOpCodes(tView, tNode, directiveIndex, allocExpando(tView, lView, def.hostVars, NO_CHANGE), def);
}
function registerHostBindingOpCodes(tView, tNode, directiveIdx, directiveVarsIdx, def) {
  ngDevMode && assertFirstCreatePass(tView);
  const hostBindings = def.hostBindings;
  if (hostBindings) {
    let hostBindingOpCodes = tView.hostBindingOpCodes;
    if (hostBindingOpCodes === null) {
      hostBindingOpCodes = tView.hostBindingOpCodes = [];
    }
    const elementIndx = ~tNode.index;
    if (lastSelectedElementIdx(hostBindingOpCodes) != elementIndx) {
      hostBindingOpCodes.push(elementIndx);
    }
    hostBindingOpCodes.push(directiveIdx, directiveVarsIdx, hostBindings);
  }
}
function lastSelectedElementIdx(hostBindingOpCodes) {
  let i = hostBindingOpCodes.length;
  while (i > 0) {
    const value = hostBindingOpCodes[--i];
    if (typeof value === 'number' && value < 0) {
      return value;
    }
  }
  return 0;
}
function saveNameToExportMap(directiveIdx, def, exportsMap) {
  if (exportsMap) {
    if (def.exportAs) {
      for (let i = 0; i < def.exportAs.length; i++) {
        exportsMap[def.exportAs[i]] = directiveIdx;
      }
    }
    if (isComponentDef(def)) exportsMap[''] = directiveIdx;
  }
}
function initTNodeFlags(tNode, index, numberOfDirectives) {
  ngDevMode && assertNotEqual(numberOfDirectives, tNode.directiveEnd - tNode.directiveStart, 'Reached the max number of directives');
  tNode.flags |= 1;
  tNode.directiveStart = index;
  tNode.directiveEnd = index + numberOfDirectives;
  tNode.providerIndexes = index;
}
function assertNoDuplicateDirectives(directives) {
  if (directives.length < 2) {
    return;
  }
  const seenDirectives = new Set();
  for (const current of directives) {
    if (seenDirectives.has(current)) {
      throw new RuntimeError(309, `Directive ${current.type.name} matches multiple times on the same element. ` + `Directives can only match an element once.`);
    }
    seenDirectives.add(current);
  }
}

function directiveHostFirstCreatePass(index, lView, type, name, directiveMatcher, bindingsEnabled, attrsIndex, localRefsIndex) {
  const tView = lView[TVIEW$1];
  ngDevMode && assertFirstCreatePass(tView);
  const tViewConsts = tView.consts;
  const attrs = getConstant(tViewConsts, attrsIndex);
  const tNode = getOrCreateTNode(tView, index, type, name, attrs);
  if (bindingsEnabled) {
    resolveDirectives(tView, lView, tNode, getConstant(tViewConsts, localRefsIndex), directiveMatcher);
  }
  tNode.mergedAttrs = mergeHostAttrs(tNode.mergedAttrs, tNode.attrs);
  if (tNode.attrs !== null) {
    computeStaticStyling(tNode, tNode.attrs, false);
  }
  if (tNode.mergedAttrs !== null) {
    computeStaticStyling(tNode, tNode.mergedAttrs, true);
  }
  if (tView.queries !== null) {
    tView.queries.elementStart(tView, tNode);
  }
  return tNode;
}
function directiveHostEndFirstCreatePass(tView, tNode) {
  ngDevMode && assertFirstCreatePass(tView);
  registerPostOrderHooks(tView, tNode);
  if (isContentQueryHost(tNode)) {
    tView.queries.elementEnd(tNode);
  }
}
function domOnlyFirstCreatePass(index, tView, type, name, attrsIndex, localRefsIndex) {
  ngDevMode && assertFirstCreatePass(tView);
  const tViewConsts = tView.consts;
  const attrs = getConstant(tViewConsts, attrsIndex);
  const tNode = getOrCreateTNode(tView, index, type, name, attrs);
  tNode.mergedAttrs = mergeHostAttrs(tNode.mergedAttrs, tNode.attrs);
  if (localRefsIndex != null) {
    const refs = getConstant(tViewConsts, localRefsIndex);
    tNode.localNames = [];
    for (let i = 0; i < refs.length; i += 2) {
      tNode.localNames.push(refs[i], -1);
    }
  }
  if (tNode.attrs !== null) {
    computeStaticStyling(tNode, tNode.attrs, false);
  }
  if (tNode.mergedAttrs !== null) {
    computeStaticStyling(tNode, tNode.mergedAttrs, true);
  }
  if (tView.queries !== null) {
    tView.queries.elementStart(tView, tNode);
  }
  return tNode;
}

const shadowRootSupported = typeof ShadowRoot !== 'undefined';
const documentSupported = typeof Document !== 'undefined';
function toInputRefArray(map) {
  return Object.keys(map).map(name => {
    const [propName, flags, transform] = map[name];
    const inputData = {
      propName: propName,
      templateName: name,
      isSignal: (flags & InputFlags.SignalBased) !== 0
    };
    if (transform) {
      inputData.transform = transform;
    }
    return inputData;
  });
}
function toOutputRefArray(map) {
  return Object.keys(map).map(name => ({
    propName: map[name],
    templateName: name
  }));
}
function verifyNotAnOrphanComponent(componentDef) {
  if ((typeof ngJitMode === 'undefined' || ngJitMode) && componentDef.debugInfo?.forbidOrphanRendering) {
    if (depsTracker.isOrphanComponent(componentDef.type)) {
      throw new RuntimeError(981, `Orphan component found! Trying to render the component ${debugStringifyTypeForError(componentDef.type)} without first loading the NgModule that declares it. It is recommended to make this component standalone in order to avoid this error. If this is not possible now, import the component's NgModule in the appropriate NgModule, or the standalone component in which you are trying to render this component. If this is a lazy import, load the NgModule lazily as well and use its module injector.`);
    }
  }
}
function createRootViewInjector(componentDef, environmentInjector, injector) {
  let realEnvironmentInjector = environmentInjector instanceof EnvironmentInjector ? environmentInjector : environmentInjector?.injector;
  if (realEnvironmentInjector && componentDef.getStandaloneInjector !== null) {
    realEnvironmentInjector = componentDef.getStandaloneInjector(realEnvironmentInjector) || realEnvironmentInjector;
  }
  const rootViewInjector = realEnvironmentInjector ? new ChainedInjector(injector, realEnvironmentInjector) : injector;
  return rootViewInjector;
}
function createRootLViewEnvironment(rootLViewInjector) {
  const rendererFactory = rootLViewInjector.get(RendererFactory2, null);
  if (rendererFactory === null) {
    throw new RuntimeError(407, ngDevMode && 'Angular was not able to inject a renderer (RendererFactory2). ' + 'Likely this is due to a broken DI hierarchy. ' + 'Make sure that any injector used to create this component has a correct parent.');
  }
  const sanitizer = rootLViewInjector.get(Sanitizer, null);
  const changeDetectionScheduler = rootLViewInjector.get(ChangeDetectionScheduler, null);
  const tracingService = rootLViewInjector.get(TracingService, null, {
    optional: true
  });
  let ngReflect = false;
  if (typeof ngDevMode === 'undefined' || ngDevMode) {
    ngReflect = rootLViewInjector.get(NG_REFLECT_ATTRS_FLAG, NG_REFLECT_ATTRS_FLAG_DEFAULT);
  }
  return {
    rendererFactory,
    sanitizer,
    changeDetectionScheduler,
    ngReflect,
    tracingService
  };
}
function createHostElement(componentDef, renderer, hostElementNamespace) {
  const tagName = inferTagNameFromDefinition(componentDef);
  const namespace = tagName === 'svg' ? SVG_NAMESPACE : tagName === 'math' ? MATH_ML_NAMESPACE : hostElementNamespace;
  return createElementNode(renderer, tagName, namespace);
}
function assertNotScriptHostElement(element) {
  const elementName = element && 'localName' in element && typeof element.localName === 'string' ? element.localName : element?.tagName;
  if (elementName?.toLowerCase() === 'script') {
    throw new RuntimeError(905, ngDevMode && `"<script>" tag is not allowed as a component host element.`);
  }
}
function inferTagNameFromDefinition(componentDef) {
  return (componentDef.selectors[0][0] || 'div').toLowerCase();
}
class ComponentFactory {
  componentDef;
  ngModule;
  selector;
  componentType;
  ngContentSelectors;
  isBoundToModule;
  cachedInputs = null;
  cachedOutputs = null;
  get inputs() {
    this.cachedInputs ??= toInputRefArray(this.componentDef.inputs);
    return this.cachedInputs;
  }
  get outputs() {
    this.cachedOutputs ??= toOutputRefArray(this.componentDef.outputs);
    return this.cachedOutputs;
  }
  constructor(componentDef, ngModule) {
    this.componentDef = componentDef;
    this.ngModule = ngModule;
    this.componentType = componentDef.type;
    this.selector = stringifyCSSSelectorList(componentDef.selectors);
    this.ngContentSelectors = componentDef.ngContentSelectors ?? [];
    this.isBoundToModule = !!ngModule;
  }
  create(injector, projectableNodes, rootSelectorOrNode, environmentInjector, directives, componentBindings, hostElementNamespace, allowNonStandaloneDirectives) {
    profiler(ProfilerEvent.DynamicComponentStart);
    const prevConsumer = setActiveConsumer(null);
    try {
      const cmpDef = this.componentDef;
      ngDevMode && verifyNotAnOrphanComponent(cmpDef);
      const rootViewInjector = createRootViewInjector(cmpDef, environmentInjector || this.ngModule, injector);
      const environment = createRootLViewEnvironment(rootViewInjector);
      const tracingService = environment.tracingService;
      if (tracingService && tracingService.componentCreate) {
        return tracingService.componentCreate(getComponentName(cmpDef), () => this.createComponentRef(environment, rootViewInjector, projectableNodes, rootSelectorOrNode, directives, componentBindings, hostElementNamespace, allowNonStandaloneDirectives));
      } else {
        return this.createComponentRef(environment, rootViewInjector, projectableNodes, rootSelectorOrNode, directives, componentBindings, hostElementNamespace, allowNonStandaloneDirectives);
      }
    } finally {
      setActiveConsumer(prevConsumer);
    }
  }
  createComponentRef(environment, rootViewInjector, projectableNodes, rootSelectorOrNode, directives, componentBindings, hostElementNamespace, allowNonStandaloneDirectives) {
    const cmpDef = this.componentDef;
    const rootTView = createRootTView(rootSelectorOrNode, cmpDef, componentBindings, directives, allowNonStandaloneDirectives);
    const hostRenderer = environment.rendererFactory.createRenderer(null, cmpDef);
    const hostElement = rootSelectorOrNode ? locateHostElement(hostRenderer, rootSelectorOrNode, cmpDef.encapsulation, rootViewInjector) : createHostElement(cmpDef, hostRenderer, hostElementNamespace ?? null);
    assertNotScriptHostElement(hostElement);
    const sharedStylesHost = rootViewInjector.get(SHARED_STYLES_HOST, null);
    const styleHost = getStyleHost(hostElement, () => rootViewInjector.get(DOCUMENT$1, null) ?? getDocument());
    if (sharedStylesHost) sharedStylesHost.addHost(styleHost);
    const hasInputBindings = componentBindings?.some(isInputBinding) || directives?.some(d => typeof d !== 'function' && d.bindings.some(isInputBinding));
    const rootLView = createLView(null, rootTView, null, 512 | getInitialLViewFlagsFromDef(cmpDef), null, null, environment, hostRenderer, rootViewInjector, null, retrieveHydrationInfo(hostElement, rootViewInjector, true));
    if (sharedStylesHost && shadowRootSupported && styleHost instanceof ShadowRoot) {
      storeLViewOnDestroy(rootLView, () => {
        sharedStylesHost.removeHost(styleHost);
      });
    }
    rootLView[HEADER_OFFSET] = hostElement;
    enterView(rootLView);
    let componentView = null;
    try {
      const hostTNode = directiveHostFirstCreatePass(HEADER_OFFSET, rootLView, 2, "#host", () => rootTView.directiveRegistry, true, 0);
      setupStaticAttributes(hostRenderer, hostElement, hostTNode);
      attachPatchData(hostElement, rootLView);
      createDirectivesInstances(rootTView, rootLView, hostTNode);
      executeContentQueries(rootTView, hostTNode, rootLView);
      directiveHostEndFirstCreatePass(rootTView, hostTNode);
      if (projectableNodes !== undefined) {
        projectNodes(hostTNode, this.ngContentSelectors, projectableNodes);
      }
      componentView = getComponentLViewByIndex(hostTNode.index, rootLView);
      rootLView[CONTEXT] = componentView[CONTEXT];
      renderView(rootTView, rootLView, null);
    } catch (e) {
      if (componentView !== null) {
        unregisterLView(componentView);
      }
      unregisterLView(rootLView);
      throw e;
    } finally {
      profiler(ProfilerEvent.DynamicComponentEnd);
      leaveView();
    }
    return new ComponentRef(this.componentType, rootLView, !!hasInputBindings);
  }
}
function createRootTView(rootSelectorOrNode, componentDef, componentBindings, directives, allowNonStandaloneDirectives) {
  const tAttributes = rootSelectorOrNode ? ['ng-version', '22.2.3'] : extractAttrsAndClassesFromSelector(componentDef.selectors[0]);
  let creationBindings = null;
  let updateBindings = null;
  let varsToAllocate = 0;
  if (componentBindings) {
    for (const binding of componentBindings) {
      varsToAllocate += binding[BINDING].requiredVars;
      if (binding.create) {
        binding.targetIdx = 0;
        (creationBindings ??= []).push(binding);
      }
      if (binding.update) {
        binding.targetIdx = 0;
        (updateBindings ??= []).push(binding);
      }
    }
  }
  if (directives) {
    for (let i = 0; i < directives.length; i++) {
      const directive = directives[i];
      if (typeof directive !== 'function') {
        for (const binding of directive.bindings) {
          varsToAllocate += binding[BINDING].requiredVars;
          const targetDirectiveIdx = i + 1;
          if (binding.create) {
            binding.targetIdx = targetDirectiveIdx;
            (creationBindings ??= []).push(binding);
          }
          if (binding.update) {
            binding.targetIdx = targetDirectiveIdx;
            (updateBindings ??= []).push(binding);
          }
        }
      }
    }
  }
  const directivesToApply = [componentDef];
  if (directives) {
    for (const directive of directives) {
      const directiveType = typeof directive === 'function' ? directive : directive.type;
      const directiveDef = ngDevMode ? getDirectiveDefOrThrow(directiveType) : getDirectiveDef(directiveType);
      if (ngDevMode && !allowNonStandaloneDirectives && !directiveDef.standalone) {
        throw new RuntimeError(907, `The ${stringifyForError(directiveType)} directive must be standalone in ` + `order to be applied to a dynamically-created component.`);
      }
      directivesToApply.push(directiveDef);
    }
  }
  const rootTView = createTView(0, null, getRootTViewTemplate(creationBindings, updateBindings), 1, varsToAllocate, directivesToApply, null, null, null, [tAttributes], null);
  return rootTView;
}
function getStyleHost(node, doc) {
  const rootNode = node.getRootNode?.();
  if (documentSupported && rootNode instanceof Document) {
    return rootNode.head;
  } else if (!rootNode) {
    return doc().head;
  } else if (shadowRootSupported && rootNode instanceof ShadowRoot) {
    return rootNode;
  } else {
    return doc().head;
  }
}
function getRootTViewTemplate(creationBindings, updateBindings) {
  if (!creationBindings && !updateBindings) {
    return null;
  }
  return flags => {
    if (flags & 1 && creationBindings) {
      for (const binding of creationBindings) {
        binding.create();
      }
    }
    if (flags & 2 && updateBindings) {
      for (const binding of updateBindings) {
        binding.update();
      }
    }
  };
}
function isInputBinding(binding) {
  const kind = binding[BINDING].kind;
  return kind === 'input' || kind === 'twoWay';
}
class ComponentRef extends ComponentRef$1 {
  _rootLView;
  _hasInputBindings;
  instance;
  hostView;
  changeDetectorRef;
  componentType;
  location;
  previousInputValues = null;
  _tNode;
  constructor(componentType, _rootLView, _hasInputBindings) {
    super();
    this._rootLView = _rootLView;
    this._hasInputBindings = _hasInputBindings;
    this._tNode = getTNode(_rootLView[TVIEW$1], HEADER_OFFSET);
    this.location = createElementRef(this._tNode, _rootLView);
    this.instance = getComponentLViewByIndex(this._tNode.index, _rootLView)[CONTEXT];
    this.hostView = this.changeDetectorRef = new ViewRef(_rootLView, undefined);
    this.componentType = componentType;
  }
  setInput(name, value) {
    if (this._hasInputBindings && ngDevMode) {
      throw new RuntimeError(317, 'Cannot call `setInput` on a component that is using the `inputBinding` or `twoWayBinding` functions.');
    }
    const tNode = this._tNode;
    this.previousInputValues ??= new Map();
    if (this.previousInputValues.has(name) && Object.is(this.previousInputValues.get(name), value)) {
      return;
    }
    const lView = this._rootLView;
    const hasSetInput = setAllInputsForProperty(tNode, lView[TVIEW$1], lView, name, value);
    this.previousInputValues.set(name, value);
    const childComponentLView = getComponentLViewByIndex(tNode.index, lView);
    markViewDirty(childComponentLView, 1);
    if (ngDevMode && !hasSetInput) {
      const cmpNameForError = stringifyForError(this.componentType);
      let message = `Can't set value of the '${name}' input on the '${cmpNameForError}' component. `;
      message += `Make sure that the '${name}' property is declared as an input using the input() or model() function or the @Input() decorator.`;
      reportUnknownPropertyError(message);
    }
  }
  get injector() {
    return new NodeInjector(this._tNode, this._rootLView);
  }
  destroy() {
    this.hostView.destroy();
  }
  onDestroy(callback) {
    this.hostView.onDestroy(callback);
  }
}
function projectNodes(tNode, ngContentSelectors, projectableNodes) {
  const projection = tNode.projection = [];
  for (let i = 0; i < ngContentSelectors.length; i++) {
    const nodesforSlot = projectableNodes[i];
    projection.push(nodesforSlot != null && nodesforSlot.length ? Array.from(nodesforSlot) : null);
  }
}

class ViewContainerRef {
  static __NG_ELEMENT_ID__ = injectViewContainerRef;
}
if (typeof ngDevMode === 'undefined' || ngDevMode) {
  registerSpecialProvider(ViewContainerRef);
}
function injectViewContainerRef() {
  const previousTNode = getCurrentTNode();
  return createContainerRef(previousTNode, getLView());
}
class R3ViewContainerRef extends ViewContainerRef {
  _lContainer;
  _hostTNode;
  _hostLView;
  constructor(_lContainer, _hostTNode, _hostLView) {
    super();
    this._lContainer = _lContainer;
    this._hostTNode = _hostTNode;
    this._hostLView = _hostLView;
  }
  get element() {
    return createElementRef(this._hostTNode, this._hostLView);
  }
  get injector() {
    return new NodeInjector(this._hostTNode, this._hostLView);
  }
  get parentInjector() {
    const parentLocation = getParentInjectorLocation(this._hostTNode, this._hostLView);
    if (hasParentInjector(parentLocation)) {
      const parentView = getParentInjectorView(parentLocation, this._hostLView);
      const injectorIndex = getParentInjectorIndex(parentLocation);
      ngDevMode && assertNodeInjector(parentView, injectorIndex);
      const parentTNode = parentView[TVIEW$1].data[injectorIndex + 8];
      return new NodeInjector(parentTNode, parentView);
    } else {
      return new NodeInjector(null, this._hostLView);
    }
  }
  clear() {
    while (this.length > 0) {
      this.remove(this.length - 1);
    }
  }
  get(index) {
    const viewRefs = getViewRefs(this._lContainer);
    return viewRefs !== null && viewRefs[index] || null;
  }
  get length() {
    return this._lContainer.length - CONTAINER_HEADER_OFFSET;
  }
  createEmbeddedView(templateRef, context, indexOrOptions) {
    let index;
    let injector;
    let onError;
    if (typeof indexOrOptions === 'number') {
      index = indexOrOptions;
    } else if (indexOrOptions != null) {
      index = indexOrOptions.index;
      injector = indexOrOptions.injector;
      onError = indexOrOptions.onError;
    }
    const dehydratedView = findMatchingDehydratedView(this._lContainer, templateRef.ssrId);
    const viewRef = templateRef.createEmbeddedViewImpl(context || {}, injector, dehydratedView);
    if (onError) {
      viewRef._lView[ON_ERROR] = onError;
    }
    this.insertImpl(viewRef, index, shouldAddViewToDom(this._hostTNode, dehydratedView));
    return viewRef;
  }
  createComponent(componentType, opts, injector, projectableNodes, environmentInjector, directives, bindings) {
    let index;
    let onError;
    if (ngDevMode) {
      assertDefined(getComponentDef(componentType), `Provided Component class doesn't contain Component definition. ` + `Please check whether provided class has @Component decorator.`);
      assertEqual(typeof opts !== 'number', true, 'It looks like Component type was provided as the first argument ' + "and a number (representing an index at which to insert the new component's " + 'host view into this container as the second argument. This combination of arguments ' + 'is incompatible. Please use an object as the second argument instead.');
    }
    const options = opts || {};
    if (ngDevMode && options.environmentInjector && options.ngModuleRef) {
      throwError(`Cannot pass both environmentInjector and ngModuleRef options to createComponent().`);
    }
    index = options.index;
    injector = options.injector;
    projectableNodes = options.projectableNodes;
    environmentInjector = options.environmentInjector || options.ngModuleRef;
    directives = options.directives;
    bindings = options.bindings;
    onError = options.onError;
    const componentFactory = new ComponentFactory(getComponentDef(componentType));
    const contextInjector = injector || this.parentInjector;
    if (!environmentInjector && componentFactory.ngModule == null) {
      const _injector = this.parentInjector;
      const result = _injector.get(EnvironmentInjector, null);
      if (result) {
        environmentInjector = result;
      }
    }
    const componentDef = getComponentDef(componentFactory.componentType ?? {});
    const dehydratedView = findMatchingDehydratedView(this._lContainer, componentDef?.id ?? null);
    const rNode = dehydratedView?.firstChild ?? null;
    const componentRef = componentFactory.create(contextInjector, projectableNodes, rNode, environmentInjector, directives, bindings, this._getHostElementNamespace());
    if (onError) {
      componentRef.hostView._lView[ON_ERROR] = onError;
    }
    this.insertImpl(componentRef.hostView, index, shouldAddViewToDom(this._hostTNode, dehydratedView));
    return componentRef;
  }
  _getHostElementNamespace() {
    if (this._hostTNode.type & 2) {
      const parentTNode = this._hostTNode.parent ?? this._hostLView[T_HOST];
      if (parentTNode !== null && parentTNode.type & 2 && typeof parentTNode.value === 'string' && parentTNode.value.toLowerCase() === 'foreignobject') {
        return null;
      }
      return parentTNode?.namespace ?? null;
    }
    return this._hostTNode.namespace;
  }
  insert(viewRef, index) {
    return this.insertImpl(viewRef, index, true);
  }
  insertImpl(viewRef, index, addToDOM) {
    const lView = viewRef._lView;
    if (ngDevMode && viewRef.destroyed) {
      throw new RuntimeError(922, ngDevMode && 'Cannot insert a destroyed View in a ViewContainer!');
    }
    if (viewAttachedToContainer(lView)) {
      const prevIdx = this.indexOf(viewRef);
      if (prevIdx !== -1) {
        this.detach(prevIdx);
      } else {
        const prevLContainer = lView[PARENT];
        ngDevMode && assertEqual(isLContainer(prevLContainer), true, 'An attached view should have its PARENT point to a container.');
        const prevVCRef = new R3ViewContainerRef(prevLContainer, prevLContainer[T_HOST], prevLContainer[PARENT]);
        prevVCRef.detach(prevVCRef.indexOf(viewRef));
      }
    }
    const adjustedIdx = this._adjustIndex(index);
    const lContainer = this._lContainer;
    addLViewToLContainer(lContainer, lView, adjustedIdx, addToDOM);
    viewRef.attachToViewContainerRef();
    addToArray(getOrCreateViewRefs(lContainer), adjustedIdx, viewRef);
    return viewRef;
  }
  move(viewRef, newIndex) {
    if (ngDevMode && viewRef.destroyed) {
      throw new RuntimeError(923, ngDevMode && 'Cannot move a destroyed View in a ViewContainer!');
    }
    return this.insert(viewRef, newIndex);
  }
  indexOf(viewRef) {
    const viewRefsArr = getViewRefs(this._lContainer);
    return viewRefsArr !== null ? viewRefsArr.indexOf(viewRef) : -1;
  }
  remove(index) {
    const adjustedIdx = this._adjustIndex(index, -1);
    const detachedView = detachView(this._lContainer, adjustedIdx);
    if (detachedView) {
      removeFromArray(getOrCreateViewRefs(this._lContainer), adjustedIdx);
      destroyLView(detachedView[TVIEW$1], detachedView);
    }
  }
  detach(index) {
    const adjustedIdx = this._adjustIndex(index, -1);
    const view = detachView(this._lContainer, adjustedIdx);
    const wasDetached = view && removeFromArray(getOrCreateViewRefs(this._lContainer), adjustedIdx) != null;
    return wasDetached ? new ViewRef(view) : null;
  }
  _adjustIndex(index, shift = 0) {
    if (index == null) {
      return this.length + shift;
    }
    if (ngDevMode) {
      assertGreaterThan(index, -1, `ViewRef index must be positive, got ${index}`);
      assertLessThan(index, this.length + 1 + shift, 'index');
    }
    return index;
  }
}
function getViewRefs(lContainer) {
  return lContainer[VIEW_REFS];
}
function getOrCreateViewRefs(lContainer) {
  return lContainer[VIEW_REFS] || (lContainer[VIEW_REFS] = []);
}
function createContainerRef(hostTNode, hostLView) {
  ngDevMode && assertTNodeType(hostTNode, 12 | 3);
  let lContainer;
  const slotValue = hostLView[hostTNode.index];
  if (isLContainer(slotValue)) {
    lContainer = slotValue;
  } else {
    lContainer = createLContainer(slotValue, hostLView, null, hostTNode);
    hostLView[hostTNode.index] = lContainer;
    addToEndOfViewTree(hostLView, lContainer);
  }
  _locateOrCreateAnchorNode(lContainer, hostLView, hostTNode, slotValue);
  return new R3ViewContainerRef(lContainer, hostTNode, hostLView);
}
function insertAnchorNode(hostLView, hostTNode) {
  const renderer = hostLView[RENDERER];
  const commentNode = renderer.createComment(ngDevMode ? 'container' : '');
  const hostNative = getNativeByTNode(hostTNode, hostLView);
  const parentOfHostNative = renderer.parentNode(hostNative);
  nativeInsertBefore(renderer, parentOfHostNative, commentNode, renderer.nextSibling(hostNative), false);
  return commentNode;
}
let _locateOrCreateAnchorNode = createAnchorNode;
let _populateDehydratedViewsInLContainer = () => false;
function populateDehydratedViewsInLContainer(lContainer, tNode, hostLView) {
  return _populateDehydratedViewsInLContainer(lContainer, tNode, hostLView);
}
function createAnchorNode(lContainer, hostLView, hostTNode, slotValue) {
  if (lContainer[NATIVE]) return;
  let commentNode;
  if (hostTNode.type & 8) {
    commentNode = unwrapRNode(slotValue);
  } else {
    commentNode = insertAnchorNode(hostLView, hostTNode);
  }
  lContainer[NATIVE] = commentNode;
}
function populateDehydratedViewsInLContainerImpl(lContainer, tNode, hostLView) {
  if (lContainer[NATIVE] && lContainer[DEHYDRATED_VIEWS]) {
    return true;
  }
  const hydrationInfo = hostLView[HYDRATION];
  const noOffsetIndex = tNode.index - HEADER_OFFSET;
  const isNodeCreationMode = !hydrationInfo || isInSkipHydrationBlock(tNode) || isDisconnectedNode$1(hydrationInfo, noOffsetIndex);
  if (isNodeCreationMode) {
    return false;
  }
  const currentRNode = getSegmentHead(hydrationInfo, noOffsetIndex);
  const serializedViews = hydrationInfo.data[CONTAINERS]?.[noOffsetIndex];
  if (serializedViews === undefined) {
    ngDevMode && console.warn('Unexpected state: no hydration info available for a given TNode, ' + 'which represents a view container.');
    return false;
  }
  const [commentNode, dehydratedViews] = locateDehydratedViewsInContainer(currentRNode, serializedViews);
  if (ngDevMode) {
    validateMatchingNode(commentNode, Node.COMMENT_NODE, null, hostLView, tNode, true);
    markRNodeAsClaimedByHydration(commentNode, false);
  }
  lContainer[NATIVE] = commentNode;
  lContainer[DEHYDRATED_VIEWS] = dehydratedViews;
  return true;
}
function locateOrCreateAnchorNode(lContainer, hostLView, hostTNode, slotValue) {
  if (!_populateDehydratedViewsInLContainer(lContainer, hostTNode, hostLView)) {
    createAnchorNode(lContainer, hostLView, hostTNode, slotValue);
  }
}
function enableLocateOrCreateContainerRefImpl() {
  _locateOrCreateAnchorNode = locateOrCreateAnchorNode;
  _populateDehydratedViewsInLContainer = populateDehydratedViewsInLContainerImpl;
}

class LQuery_ {
  queryList;
  matches = null;
  constructor(queryList) {
    this.queryList = queryList;
  }
  clone() {
    return new LQuery_(this.queryList);
  }
  setDirty() {
    this.queryList.setDirty();
  }
}
class LQueries_ {
  queries;
  constructor(queries = []) {
    this.queries = queries;
  }
  createEmbeddedView(tView) {
    const tQueries = tView.queries;
    if (tQueries !== null) {
      const noOfInheritedQueries = tView.contentQueries !== null ? tView.contentQueries[0] : tQueries.length;
      const viewLQueries = [];
      for (let i = 0; i < noOfInheritedQueries; i++) {
        const tQuery = tQueries.getByIndex(i);
        const parentLQuery = this.queries[tQuery.indexInDeclarationView];
        viewLQueries.push(parentLQuery.clone());
      }
      return new LQueries_(viewLQueries);
    }
    return null;
  }
  insertView(tView) {
    this.dirtyQueriesWithMatches(tView);
  }
  detachView(tView) {
    this.dirtyQueriesWithMatches(tView);
  }
  finishViewCreation(tView) {
    this.dirtyQueriesWithMatches(tView);
  }
  dirtyQueriesWithMatches(tView) {
    for (let i = 0; i < this.queries.length; i++) {
      if (getTQuery(tView, i).matches !== null) {
        this.queries[i].setDirty();
      }
    }
  }
}
class TQueryMetadata_ {
  flags;
  read;
  predicate;
  constructor(predicate, flags, read = null) {
    this.flags = flags;
    this.read = read;
    if (typeof predicate === 'string') {
      this.predicate = splitQueryMultiSelectors(predicate);
    } else {
      this.predicate = predicate;
    }
  }
}
class TQueries_ {
  queries;
  constructor(queries = []) {
    this.queries = queries;
  }
  elementStart(tView, tNode) {
    ngDevMode && assertFirstCreatePass(tView, 'Queries should collect results on the first template pass only');
    for (let i = 0; i < this.queries.length; i++) {
      this.queries[i].elementStart(tView, tNode);
    }
  }
  elementEnd(tNode) {
    for (let i = 0; i < this.queries.length; i++) {
      this.queries[i].elementEnd(tNode);
    }
  }
  embeddedTView(tNode) {
    let queriesForTemplateRef = null;
    for (let i = 0; i < this.length; i++) {
      const childQueryIndex = queriesForTemplateRef !== null ? queriesForTemplateRef.length : 0;
      const tqueryClone = this.getByIndex(i).embeddedTView(tNode, childQueryIndex);
      if (tqueryClone) {
        tqueryClone.indexInDeclarationView = i;
        if (queriesForTemplateRef !== null) {
          queriesForTemplateRef.push(tqueryClone);
        } else {
          queriesForTemplateRef = [tqueryClone];
        }
      }
    }
    return queriesForTemplateRef !== null ? new TQueries_(queriesForTemplateRef) : null;
  }
  template(tView, tNode) {
    ngDevMode && assertFirstCreatePass(tView, 'Queries should collect results on the first template pass only');
    for (let i = 0; i < this.queries.length; i++) {
      this.queries[i].template(tView, tNode);
    }
  }
  getByIndex(index) {
    ngDevMode && assertIndexInRange(this.queries, index);
    return this.queries[index];
  }
  get length() {
    return this.queries.length;
  }
  track(tquery) {
    this.queries.push(tquery);
  }
}
class TQuery_ {
  metadata;
  matches = null;
  indexInDeclarationView = -1;
  crossesNgTemplate = false;
  _declarationNodeIndex;
  _appliesToNextNode = true;
  constructor(metadata, nodeIndex = -1) {
    this.metadata = metadata;
    this._declarationNodeIndex = nodeIndex;
  }
  elementStart(tView, tNode) {
    if (this.isApplyingToNode(tNode)) {
      this.matchTNode(tView, tNode);
    }
  }
  elementEnd(tNode) {
    if (this._declarationNodeIndex === tNode.index) {
      this._appliesToNextNode = false;
    }
  }
  template(tView, tNode) {
    this.elementStart(tView, tNode);
  }
  embeddedTView(tNode, childQueryIndex) {
    if (this.isApplyingToNode(tNode)) {
      this.crossesNgTemplate = true;
      this.addMatch(-tNode.index, childQueryIndex);
      return new TQuery_(this.metadata);
    }
    return null;
  }
  isApplyingToNode(tNode) {
    if (this._appliesToNextNode && (this.metadata.flags & 1) !== 1) {
      const declarationNodeIdx = this._declarationNodeIndex;
      let parent = tNode.parent;
      while (parent !== null && parent.type & 8 && parent.index !== declarationNodeIdx) {
        parent = parent.parent;
      }
      return declarationNodeIdx === (parent !== null ? parent.index : -1);
    }
    return this._appliesToNextNode;
  }
  matchTNode(tView, tNode) {
    const predicate = this.metadata.predicate;
    if (Array.isArray(predicate)) {
      for (let i = 0; i < predicate.length; i++) {
        const name = predicate[i];
        this.matchTNodeWithReadOption(tView, tNode, getIdxOfMatchingSelector(tNode, name));
        this.matchTNodeWithReadOption(tView, tNode, locateDirectiveOrProvider(tNode, tView, name, false, false));
      }
    } else {
      if (predicate === TemplateRef) {
        if (tNode.type & 4) {
          this.matchTNodeWithReadOption(tView, tNode, -1);
        }
      } else {
        this.matchTNodeWithReadOption(tView, tNode, locateDirectiveOrProvider(tNode, tView, predicate, false, false));
      }
    }
  }
  matchTNodeWithReadOption(tView, tNode, nodeMatchIdx) {
    if (nodeMatchIdx !== null) {
      const read = this.metadata.read;
      if (read !== null) {
        if (read === ElementRef || read === ViewContainerRef || read === Injector || read === TemplateRef && tNode.type & 4) {
          this.addMatch(tNode.index, -2);
        } else {
          const directiveOrProviderIdx = locateDirectiveOrProvider(tNode, tView, read, false, false);
          if (directiveOrProviderIdx !== null) {
            this.addMatch(tNode.index, directiveOrProviderIdx);
          }
        }
      } else {
        this.addMatch(tNode.index, nodeMatchIdx);
      }
    }
  }
  addMatch(tNodeIdx, matchIdx) {
    if (this.matches === null) {
      this.matches = [tNodeIdx, matchIdx];
    } else {
      this.matches.push(tNodeIdx, matchIdx);
    }
  }
}
function getIdxOfMatchingSelector(tNode, selector) {
  const localNames = tNode.localNames;
  if (localNames !== null) {
    for (let i = 0; i < localNames.length; i += 2) {
      if (localNames[i] === selector) {
        return localNames[i + 1];
      }
    }
  }
  return null;
}
function createResultByTNodeType(tNode, currentView) {
  if (tNode.type & (3 | 8)) {
    return createElementRef(tNode, currentView);
  } else if (tNode.type & 4) {
    return createTemplateRef(tNode, currentView);
  }
  return null;
}
function createResultForNode(lView, tNode, matchingIdx, read) {
  if (matchingIdx === -1) {
    return createResultByTNodeType(tNode, lView);
  } else if (matchingIdx === -2) {
    return createSpecialToken(lView, tNode, read);
  } else {
    return getNodeInjectable(lView, lView[TVIEW$1], matchingIdx, tNode);
  }
}
function createSpecialToken(lView, tNode, read) {
  if (read === ElementRef) {
    return createElementRef(tNode, lView);
  } else if (read === TemplateRef) {
    return createTemplateRef(tNode, lView);
  } else if (read === ViewContainerRef) {
    ngDevMode && assertTNodeType(tNode, 3 | 12);
    return createContainerRef(tNode, lView);
  } else if (read === Injector) {
    return new NodeInjector(tNode, lView);
  } else {
    ngDevMode && throwError(`Special token to read should be one of ElementRef, TemplateRef, ViewContainerRef or Injector but got ${stringify(read)}.`);
  }
}
function materializeViewResults(tView, lView, tQuery, queryIndex) {
  const lQuery = lView[QUERIES].queries[queryIndex];
  if (lQuery.matches === null) {
    const tViewData = tView.data;
    const tQueryMatches = tQuery.matches;
    const result = [];
    for (let i = 0; tQueryMatches !== null && i < tQueryMatches.length; i += 2) {
      const matchedNodeIdx = tQueryMatches[i];
      if (matchedNodeIdx < 0) {
        result.push(null);
      } else {
        ngDevMode && assertIndexInRange(tViewData, matchedNodeIdx);
        const tNode = tViewData[matchedNodeIdx];
        result.push(createResultForNode(lView, tNode, tQueryMatches[i + 1], tQuery.metadata.read));
      }
    }
    lQuery.matches = result;
  }
  return lQuery.matches;
}
function collectQueryResults(tView, lView, queryIndex, result) {
  const tQuery = tView.queries.getByIndex(queryIndex);
  const tQueryMatches = tQuery.matches;
  if (tQueryMatches !== null) {
    const lViewResults = materializeViewResults(tView, lView, tQuery, queryIndex);
    for (let i = 0; i < tQueryMatches.length; i += 2) {
      const tNodeIdx = tQueryMatches[i];
      if (tNodeIdx > 0) {
        result.push(lViewResults[i / 2]);
      } else {
        const childQueryIndex = tQueryMatches[i + 1];
        const declarationLContainer = lView[-tNodeIdx];
        ngDevMode && assertLContainer(declarationLContainer);
        for (let i = CONTAINER_HEADER_OFFSET; i < declarationLContainer.length; i++) {
          const embeddedLView = declarationLContainer[i];
          if (embeddedLView[DECLARATION_LCONTAINER] === embeddedLView[PARENT]) {
            collectQueryResults(embeddedLView[TVIEW$1], embeddedLView, childQueryIndex, result);
          }
        }
        if (declarationLContainer[MOVED_VIEWS] !== null) {
          const embeddedLViews = declarationLContainer[MOVED_VIEWS];
          for (let i = 0; i < embeddedLViews.length; i++) {
            const embeddedLView = embeddedLViews[i];
            collectQueryResults(embeddedLView[TVIEW$1], embeddedLView, childQueryIndex, result);
          }
        }
      }
    }
  }
  return result;
}
function loadQueryInternal(lView, queryIndex) {
  ngDevMode && assertDefined(lView[QUERIES], 'LQueries should be defined when trying to load a query');
  ngDevMode && assertIndexInRange(lView[QUERIES].queries, queryIndex);
  return lView[QUERIES].queries[queryIndex].queryList;
}
function createLQuery(tView, lView, flags) {
  const queryList = new QueryList((flags & 4) === 4);
  storeCleanupWithContext(tView, lView, queryList, queryList.destroy);
  const lQueries = (lView[QUERIES] ??= new LQueries_()).queries;
  return lQueries.push(new LQuery_(queryList)) - 1;
}
function createViewQuery(predicate, flags, read) {
  ngDevMode && assertNumber(flags, 'Expecting flags');
  const tView = getTView();
  if (tView.firstCreatePass) {
    createTQuery(tView, new TQueryMetadata_(predicate, flags, read), -1);
    if ((flags & 2) === 2) {
      tView.staticViewQueries = true;
    }
  }
  return createLQuery(tView, getLView(), flags);
}
function createContentQuery(directiveIndex, predicate, flags, read) {
  ngDevMode && assertNumber(flags, 'Expecting flags');
  const tView = getTView();
  if (tView.firstCreatePass) {
    const tNode = getCurrentTNode();
    createTQuery(tView, new TQueryMetadata_(predicate, flags, read), tNode.index);
    saveContentQueryAndDirectiveIndex(tView, directiveIndex);
    if ((flags & 2) === 2) {
      tView.staticContentQueries = true;
    }
  }
  return createLQuery(tView, getLView(), flags);
}
function splitQueryMultiSelectors(locator) {
  return locator.split(',').map(s => s.trim());
}
function createTQuery(tView, metadata, nodeIndex) {
  if (tView.queries === null) tView.queries = new TQueries_();
  tView.queries.track(new TQuery_(metadata, nodeIndex));
}
function saveContentQueryAndDirectiveIndex(tView, directiveIndex) {
  const tViewContentQueries = tView.contentQueries || (tView.contentQueries = []);
  const lastSavedDirectiveIndex = tViewContentQueries.length ? tViewContentQueries[tViewContentQueries.length - 1] : -1;
  if (directiveIndex !== lastSavedDirectiveIndex) {
    tViewContentQueries.push(tView.queries.length - 1, directiveIndex);
  }
}
function getTQuery(tView, index) {
  ngDevMode && assertDefined(tView.queries, 'TQueries must be defined to retrieve a TQuery');
  return tView.queries.getByIndex(index);
}
function getQueryResults(lView, queryIndex) {
  const tView = lView[TVIEW$1];
  const tQuery = getTQuery(tView, queryIndex);
  return tQuery.crossesNgTemplate ? collectQueryResults(tView, lView, queryIndex, []) : materializeViewResults(tView, lView, tQuery, queryIndex);
}

function createQuerySignalFn(firstOnly, required, opts) {
  let node;
  const signalFn = createComputed(() => {
    node._dirtyCounter();
    const value = refreshSignalQuery(node, firstOnly);
    if (required && value === undefined) {
      throw new RuntimeError(-951, ngDevMode && 'Child query result is required but no value is available.');
    }
    return value;
  });
  node = signalFn[SIGNAL];
  node._dirtyCounter = signal(0);
  node._flatValue = undefined;
  if (ngDevMode) {
    signalFn.toString = () => `[Query Signal]`;
    node.debugName = opts?.debugName;
  }
  return signalFn;
}
function createSingleResultOptionalQuerySignalFn(opts) {
  return createQuerySignalFn(true, false, opts);
}
function createSingleResultRequiredQuerySignalFn(opts) {
  return createQuerySignalFn(true, true, opts);
}
function createMultiResultQuerySignalFn(opts) {
  return createQuerySignalFn(false, false, opts);
}
function bindQueryToSignal(target, queryIndex) {
  const node = target[SIGNAL];
  node._lView = getLView();
  node._queryIndex = queryIndex;
  node._queryList = loadQueryInternal(node._lView, queryIndex);
  node._queryList.onDirty(() => node._dirtyCounter.update(v => v + 1));
}
function refreshSignalQuery(node, firstOnly) {
  const lView = node._lView;
  const queryIndex = node._queryIndex;
  if (lView === undefined || queryIndex === undefined || lView[FLAGS] & 4) {
    return firstOnly ? undefined : EMPTY_ARRAY;
  }
  const queryList = loadQueryInternal(lView, queryIndex);
  const results = getQueryResults(lView, queryIndex);
  queryList.reset(results, unwrapElementRef);
  if (firstOnly) {
    return queryList.first;
  } else {
    const resultChanged = queryList._changesDetected;
    if (resultChanged || node._flatValue === undefined) {
      return node._flatValue = queryList.toArray();
    }
    return node._flatValue;
  }
}

function isPromise(obj) {
  return !!obj && typeof obj.then === 'function';
}
function isSubscribable(obj) {
  return !!obj && typeof obj.subscribe === 'function';
}

let NgModuleRef$1 = class NgModuleRef {};
let NgModuleFactory$1 = class NgModuleFactory {};

function createNgModule(ngModule, parentInjector) {
  return new NgModuleRef(ngModule, parentInjector ?? null, []);
}
class NgModuleRef extends NgModuleRef$1 {
  ngModuleType;
  _parent;
  _bootstrapComponents = [];
  _r3Injector;
  instance;
  destroyCbs = [];
  constructor(ngModuleType, _parent, additionalProviders, runInjectorInitializers = true) {
    super();
    this.ngModuleType = ngModuleType;
    this._parent = _parent;
    const ngModuleDef = getNgModuleDef(ngModuleType);
    ngDevMode && assertDefined(ngModuleDef, `NgModule '${stringify(ngModuleType)}' is not a subtype of 'NgModuleType'.`);
    this._bootstrapComponents = maybeUnwrapFn(ngModuleDef.bootstrap);
    this._r3Injector = createInjectorWithoutInjectorInstances(ngModuleType, _parent, [{
      provide: NgModuleRef$1,
      useValue: this
    }, ...additionalProviders], stringify(ngModuleType), new Set(['environment']));
    if (runInjectorInitializers) {
      this.resolveInjectorInitializers();
    }
  }
  resolveInjectorInitializers() {
    this._r3Injector.resolveInjectorInitializers();
    this.instance = this._r3Injector.get(this.ngModuleType);
  }
  get injector() {
    return this._r3Injector;
  }
  destroy() {
    ngDevMode && assertDefined(this.destroyCbs, 'NgModule already destroyed');
    const injector = this._r3Injector;
    !injector.destroyed && injector.destroy();
    this.destroyCbs.forEach(fn => fn());
    this.destroyCbs = null;
  }
  onDestroy(callback) {
    ngDevMode && assertDefined(this.destroyCbs, 'NgModule already destroyed');
    this.destroyCbs.push(callback);
  }
}
class NgModuleFactory extends NgModuleFactory$1 {
  moduleType;
  constructor(moduleType) {
    super();
    this.moduleType = moduleType;
  }
  create(parentInjector) {
    return new NgModuleRef(this.moduleType, parentInjector, []);
  }
}
function createNgModuleRefWithProviders(moduleType, parentInjector, additionalProviders) {
  return new NgModuleRef(moduleType, parentInjector, additionalProviders, false);
}
class EnvironmentNgModuleRefAdapter extends NgModuleRef$1 {
  injector;
  instance = null;
  constructor(config) {
    super();
    const injector = new R3Injector([...config.providers, {
      provide: NgModuleRef$1,
      useValue: this
    }], config.parent || getNullInjector(), config.debugName, new Set(['environment']));
    this.injector = injector;
    if (config.runEnvironmentInitializers) {
      injector.resolveInjectorInitializers();
    }
  }
  destroy() {
    this.injector.destroy();
  }
  onDestroy(callback) {
    this.injector.onDestroy(callback);
  }
}
function createEnvironmentInjector(providers, parent, debugName = null) {
  const adapter = new EnvironmentNgModuleRefAdapter({
    providers,
    parent,
    debugName,
    runEnvironmentInitializers: true
  });
  return adapter.injector;
}

class StandaloneService {
  _injector;
  cachedInjectors = new Map();
  constructor(_injector) {
    this._injector = _injector;
  }
  getOrCreateStandaloneInjector(componentDef) {
    if (!componentDef.standalone) {
      return null;
    }
    if (!this.cachedInjectors.has(componentDef)) {
      const providers = internalImportProvidersFrom(false, componentDef.type);
      const standaloneInjector = providers.length > 0 ? createEnvironmentInjector([providers], this._injector, typeof ngDevMode !== 'undefined' && ngDevMode ? `Standalone[${componentDef.type.name}]` : '') : null;
      this.cachedInjectors.set(componentDef, standaloneInjector);
    }
    return this.cachedInjectors.get(componentDef);
  }
  ngOnDestroy() {
    try {
      for (const injector of this.cachedInjectors.values()) {
        if (injector !== null) {
          injector.destroy();
        }
      }
    } finally {
      this.cachedInjectors.clear();
    }
  }
  static ɵprov =
  /* @__PURE__ */
  __defineInjectable({
    token: StandaloneService,
    providedIn: 'environment',
    factory: () => new StandaloneService(__inject(EnvironmentInjector))
  });
}

function ɵɵdefineComponent(componentDefinition) {
  return noSideEffects(() => {
    (typeof ngDevMode === 'undefined' || ngDevMode) && initNgDevMode();
    const baseDef = getNgDirectiveDef(componentDefinition);
    const def = {
      ...baseDef,
      decls: componentDefinition.decls,
      vars: componentDefinition.vars,
      template: componentDefinition.template,
      consts: componentDefinition.consts || null,
      ngContentSelectors: componentDefinition.ngContentSelectors,
      onPush: componentDefinition.changeDetection !== ChangeDetectionStrategy.Eager,
      directiveDefs: null,
      pipeDefs: null,
      dependencies: baseDef.standalone && componentDefinition.dependencies || null,
      getStandaloneInjector: baseDef.standalone ? parentInjector => {
        return parentInjector.get(StandaloneService).getOrCreateStandaloneInjector(def);
      } : null,
      getExternalStyles: null,
      signals: componentDefinition.signals ?? false,
      data: componentDefinition.data || {},
      encapsulation: componentDefinition.encapsulation || ViewEncapsulation.Emulated,
      styles: componentDefinition.styles || EMPTY_ARRAY,
      _: null,
      schemas: componentDefinition.schemas || null,
      tView: null,
      id: ''
    };
    if (baseDef.standalone) {
      performanceMarkFeature('NgStandalone');
    }
    initFeatures(def);
    const dependencies = componentDefinition.dependencies;
    def.directiveDefs = extractDefListOrFactory(dependencies, extractDirectiveDef);
    def.pipeDefs = extractDefListOrFactory(dependencies, getPipeDef$1);
    def.id = getComponentId(def);
    return def;
  });
}
function extractDirectiveDef(type) {
  return getComponentDef(type) || getDirectiveDef(type);
}
function ɵɵdefineNgModule(def) {
  return noSideEffects(() => {
    const res = {
      type: def.type,
      bootstrap: def.bootstrap || EMPTY_ARRAY,
      declarations: def.declarations || EMPTY_ARRAY,
      imports: def.imports || EMPTY_ARRAY,
      exports: def.exports || EMPTY_ARRAY,
      transitiveCompileScopes: null,
      schemas: def.schemas || null,
      id: def.id || null
    };
    return res;
  });
}
function parseAndConvertInputsForDefinition(obj, declaredInputs) {
  if (obj == null) return EMPTY_OBJ;
  const newLookup = {};
  for (const minifiedKey in obj) {
    if (Object.hasOwn(obj, minifiedKey)) {
      const value = obj[minifiedKey];
      let publicName;
      let declaredName;
      let inputFlags;
      let transform;
      if (Array.isArray(value)) {
        inputFlags = value[0];
        publicName = value[1];
        declaredName = value[2] ?? publicName;
        transform = value[3] || null;
      } else {
        publicName = value;
        declaredName = value;
        inputFlags = InputFlags.None;
        transform = null;
      }
      newLookup[publicName] = [minifiedKey, inputFlags, transform];
      declaredInputs[publicName] = declaredName;
    }
  }
  return newLookup;
}
function parseAndConvertOutputsForDefinition(obj) {
  if (obj == null) return EMPTY_OBJ;
  const newLookup = {};
  for (const minifiedKey in obj) {
    if (Object.hasOwn(obj, minifiedKey)) {
      newLookup[obj[minifiedKey]] = minifiedKey;
    }
  }
  return newLookup;
}
function ɵɵdefineDirective(directiveDefinition) {
  return noSideEffects(() => {
    const def = getNgDirectiveDef(directiveDefinition);
    initFeatures(def);
    return def;
  });
}
function ɵɵdefinePipe(pipeDef) {
  return {
    type: pipeDef.type,
    name: pipeDef.name,
    factory: null,
    pure: pipeDef.pure !== false,
    standalone: pipeDef.standalone ?? true,
    onDestroy: pipeDef.type.prototype.ngOnDestroy || null
  };
}
function getNgDirectiveDef(directiveDefinition) {
  const declaredInputs = {};
  return {
    type: directiveDefinition.type,
    providersResolver: null,
    viewProvidersResolver: null,
    factory: null,
    hostBindings: directiveDefinition.hostBindings || null,
    hostVars: directiveDefinition.hostVars || 0,
    hostAttrs: directiveDefinition.hostAttrs || null,
    contentQueries: directiveDefinition.contentQueries || null,
    declaredInputs: declaredInputs,
    inputConfig: directiveDefinition.inputs || EMPTY_OBJ,
    exportAs: directiveDefinition.exportAs || null,
    standalone: directiveDefinition.standalone ?? true,
    signals: directiveDefinition.signals === true,
    selectors: directiveDefinition.selectors || EMPTY_ARRAY,
    viewQuery: directiveDefinition.viewQuery || null,
    features: directiveDefinition.features || null,
    setInput: null,
    resolveHostDirectives: null,
    hostDirectives: null,
    controlDef: null,
    signalFormsInputPresence: null,
    inputs: parseAndConvertInputsForDefinition(directiveDefinition.inputs, declaredInputs),
    outputs: parseAndConvertOutputsForDefinition(directiveDefinition.outputs),
    debugInfo: null
  };
}
function initFeatures(definition) {
  definition.features?.forEach(fn => fn(definition));
}
function extractDefListOrFactory(dependencies, defExtractor) {
  if (!dependencies) {
    return null;
  }
  return () => {
    const resolvedDependencies = typeof dependencies === 'function' ? dependencies() : dependencies;
    const result = [];
    for (const dep of resolvedDependencies) {
      const definition = defExtractor(dep);
      if (definition !== null) {
        result.push(definition);
      }
    }
    return result;
  };
}
const GENERATED_COMP_IDS = new Map();
function getComponentId(componentDef) {
  let hash = 0;
  const componentDefConsts = typeof componentDef.consts === 'function' ? '' : componentDef.consts;
  const hashSelectors = [componentDef.selectors, componentDef.ngContentSelectors, componentDef.hostVars, componentDef.hostAttrs, componentDefConsts, componentDef.vars, componentDef.decls, componentDef.encapsulation, componentDef.standalone, componentDef.signals, componentDef.exportAs, JSON.stringify(componentDef.inputs), JSON.stringify(componentDef.outputs), Object.getOwnPropertyNames(componentDef.type.prototype), !!componentDef.contentQueries, !!componentDef.viewQuery];
  if (typeof ngDevMode === 'undefined' || ngDevMode) {
    for (const item of hashSelectors) {
      assertNotEqual(typeof item, 'function', 'Internal error: attempting to use a function in component id computation logic.');
    }
  }
  for (const char of hashSelectors.join('|')) {
    hash = Math.imul(31, hash) + char.charCodeAt(0) << 0;
  }
  hash += 2147483647 + 1;
  const compId = 'c' + hash;
  if ((typeof ngDevMode === 'undefined' || ngDevMode) && (typeof ngServerMode === 'undefined' || !ngServerMode)) {
    if (GENERATED_COMP_IDS.has(compId)) {
      const previousCompDefType = GENERATED_COMP_IDS.get(compId);
      if (previousCompDefType !== componentDef.type) {
        console.warn(formatRuntimeError(-912, `Component ID generation collision detected. Components '${previousCompDefType.name}' and '${componentDef.type.name}' with selector '${stringifyCSSSelectorList(componentDef.selectors)}' generated the same component ID. To fix this, you can change the selector of one of those components or add an extra host attribute to force a different ID.`));
      }
    } else {
      GENERATED_COMP_IDS.set(compId, componentDef.type);
    }
  }
  return compId;
}

const ASYNC_COMPONENT_METADATA_FN = '__ngAsyncComponentMetadataFn__';
const ASYNC_METADATA_LOADED = '__ngAsyncMetadataLoaded__';
function getAsyncClassMetadataFn(type) {
  const componentClass = type;
  if (componentClass[ASYNC_COMPONENT_METADATA_FN] === ASYNC_METADATA_LOADED) {
    return null;
  }
  return componentClass[ASYNC_COMPONENT_METADATA_FN] ?? null;
}
function setClassMetadataAsync(type, dependencyLoaderFn, metadataSetterFn) {
  const componentClass = type;
  componentClass[ASYNC_COMPONENT_METADATA_FN] = () => Promise.all(dependencyLoaderFn()).then(dependencies => {
    metadataSetterFn(...dependencies);
    componentClass[ASYNC_COMPONENT_METADATA_FN] = ASYNC_METADATA_LOADED;
    return dependencies;
  });
  return componentClass[ASYNC_COMPONENT_METADATA_FN];
}
function setClassMetadata(type, decorators, ctorParameters, propDecorators) {
  return noSideEffects(() => {
    const clazz = type;
    if (decorators !== null) {
      if (Object.hasOwn(clazz, 'decorators') && clazz.decorators !== undefined) {
        clazz.decorators.push(...decorators);
      } else {
        clazz.decorators = decorators;
      }
    }
    if (ctorParameters !== null) {
      clazz.ctorParameters = ctorParameters;
    }
    if (propDecorators !== null) {
      if (Object.hasOwn(clazz, 'propDecorators') && clazz.propDecorators !== undefined) {
        clazz.propDecorators = {
          ...clazz.propDecorators,
          ...propDecorators
        };
      } else {
        clazz.propDecorators = propDecorators;
      }
    }
  });
}

const APP_INITIALIZER = new InjectionToken(ngDevMode ? 'Application Initializer' : '');
function provideAppInitializer(initializerFn) {
  return makeEnvironmentProviders([{
    provide: APP_INITIALIZER,
    multi: true,
    useValue: initializerFn
  }]);
}
class ApplicationInitStatus {
  resolve;
  reject;
  initialized = false;
  done = false;
  donePromise = new Promise((res, rej) => {
    this.resolve = res;
    this.reject = rej;
  });
  appInits = inject(APP_INITIALIZER, {
    optional: true
  }) ?? [];
  injector = inject(Injector);
  constructor() {
    if ((typeof ngDevMode === 'undefined' || ngDevMode) && !Array.isArray(this.appInits)) {
      throw new RuntimeError(-209, 'Unexpected type of the `APP_INITIALIZER` token value ' + `(expected an array, but got ${typeof this.appInits}). ` + 'Please check that the `APP_INITIALIZER` token is configured as a ' + '`multi: true` provider.');
    }
  }
  runInitializers() {
    if (this.initialized) {
      return;
    }
    const asyncInitPromises = [];
    for (const appInits of this.appInits) {
      const initResult = runInInjectionContext(this.injector, appInits);
      if (isPromise(initResult)) {
        asyncInitPromises.push(initResult);
      } else if (isSubscribable(initResult)) {
        const observableAsPromise = new Promise((resolve, reject) => {
          initResult.subscribe({
            complete: resolve,
            error: reject
          });
        });
        asyncInitPromises.push(observableAsPromise);
      }
    }
    const complete = () => {
      this.done = true;
      this.resolve();
    };
    Promise.all(asyncInitPromises).then(() => {
      complete();
    }).catch(e => {
      this.reject(e);
    });
    if (asyncInitPromises.length === 0) {
      complete();
    }
    this.initialized = true;
  }
  static ɵfac = function ApplicationInitStatus_Factory(__ngFactoryType__) {
    return new (__ngFactoryType__ || ApplicationInitStatus)();
  };
  static ɵprov = /*@__PURE__*/ɵɵdefineService({
    token: ApplicationInitStatus,
    factory: ApplicationInitStatus.ɵfac
  });
}
(() => {
  (typeof ngDevMode === "undefined" || ngDevMode) && setClassMetadata(ApplicationInitStatus, [{
    type: Service
  }], () => [], null);
})();

let componentResourceResolutionQueue = new Map();
const componentDefPendingResolution = new Set();
async function resolveComponentResources(resourceResolver) {
  const currentQueue = componentResourceResolutionQueue;
  componentResourceResolutionQueue = new Map();
  const urlCache = new Map();
  function cachedResourceResolve(url) {
    const promiseCached = urlCache.get(url);
    if (promiseCached) {
      return promiseCached;
    }
    const promise = resourceResolver(url).then(response => unwrapResponse(url, response));
    urlCache.set(url, promise);
    return promise;
  }
  const resolutionPromises = Array.from(currentQueue).map(async ([type, component]) => {
    if (component.styleUrl && component.styleUrls?.length) {
      throw new Error('@Component cannot define both `styleUrl` and `styleUrls`. ' + 'Use `styleUrl` if the component has one stylesheet, or `styleUrls` if it has multiple');
    }
    const componentTasks = [];
    if (component.templateUrl) {
      componentTasks.push(cachedResourceResolve(component.templateUrl).then(template => {
        component.template = template;
      }));
    }
    const styles = typeof component.styles === 'string' ? [component.styles] : component.styles ?? [];
    component.styles = styles;
    let {
      styleUrl,
      styleUrls
    } = component;
    if (styleUrl) {
      styleUrls = [styleUrl];
      component.styleUrl = undefined;
    }
    if (styleUrls?.length) {
      const allFetched = Promise.all(styleUrls.map(url => cachedResourceResolve(url))).then(fetchedStyles => {
        styles.push(...fetchedStyles);
        component.styleUrls = undefined;
      });
      componentTasks.push(allFetched);
    }
    await Promise.all(componentTasks);
    componentDefPendingResolution.delete(type);
  });
  await Promise.all(resolutionPromises);
}
function maybeQueueResolutionOfComponentResources(type, metadata) {
  if (componentNeedsResolution(metadata)) {
    componentResourceResolutionQueue.set(type, metadata);
    componentDefPendingResolution.add(type);
  }
}
function isComponentDefPendingResolution(type) {
  return componentDefPendingResolution.has(type);
}
function componentNeedsResolution(component) {
  return !!(component.templateUrl && !Object.hasOwn(component, 'template') || component.styleUrls?.length || component.styleUrl);
}
function clearResolutionOfComponentResourcesQueue() {
  const old = componentResourceResolutionQueue;
  componentResourceResolutionQueue = new Map();
  return old;
}
function restoreComponentResolutionQueue(queue) {
  componentDefPendingResolution.clear();
  for (const type of queue.keys()) {
    componentDefPendingResolution.add(type);
  }
  componentResourceResolutionQueue = queue;
}
function isComponentResourceResolutionQueueEmpty() {
  return componentResourceResolutionQueue.size === 0;
}
async function unwrapResponse(url, response) {
  if (typeof response === 'string') {
    return response;
  }
  if (response.status !== undefined && response.status !== 200) {
    throw new RuntimeError(918, ngDevMode && `Could not load resource: ${url}. Response status: ${response.status}`);
  }
  return response.text();
}

const modules = new Map();
let checkForDuplicateNgModules = true;
function assertSameOrNotExisting(id, type, incoming) {
  if (type && type !== incoming && checkForDuplicateNgModules) {
    throw new RuntimeError(921, ngDevMode && `Duplicate module registered for ${id} - ${stringify(type)} vs ${stringify(type.name)}`);
  }
}
function registerNgModuleType(ngModuleType, id) {
  const existing = modules.get(id) || null;
  assertSameOrNotExisting(id, existing, ngModuleType);
  modules.set(id, ngModuleType);
}
function getRegisteredNgModuleType(id) {
  return modules.get(id);
}
function setAllowDuplicateNgModuleIdsForTest(allowDuplicates) {
  checkForDuplicateNgModules = !allowDuplicates;
}

function ɵɵControlFeature(passThroughInput) {
  return definition => {
    definition.controlDef = {
      create: (inst, host) => {
        inst?.ɵngControlCreate(host);
      },
      update: (inst, host) => {
        inst?.ɵngControlUpdate?.(host);
      },
      passThroughInput
    };
  };
}

function ɵɵHostDirectivesFeature(rawHostDirectives) {
  const feature = definition => {
    const isEager = Array.isArray(rawHostDirectives);
    if (definition.hostDirectives === null) {
      definition.resolveHostDirectives = resolveHostDirectives;
      definition.hostDirectives = isEager ? rawHostDirectives.map(createHostDirectiveDef) : [rawHostDirectives];
    } else if (isEager) {
      definition.hostDirectives.unshift(...rawHostDirectives.map(createHostDirectiveDef));
    } else {
      definition.hostDirectives.unshift(rawHostDirectives);
    }
  };
  feature.ngInherit = true;
  return feature;
}
function resolveHostDirectives(matches) {
  const allDirectiveDefs = [];
  let hasComponent = false;
  let hostDirectiveDefs = null;
  let hostDirectiveRanges = null;
  for (let i = 0; i < matches.length; i++) {
    const def = matches[i];
    if (def.hostDirectives !== null) {
      const start = allDirectiveDefs.length;
      hostDirectiveDefs ??= new Map();
      hostDirectiveRanges ??= new Map();
      findHostDirectiveDefs(def, allDirectiveDefs, hostDirectiveDefs, matches);
      hostDirectiveRanges.set(def, [start, allDirectiveDefs.length - 1]);
    }
    if (i === 0 && isComponentDef(def)) {
      hasComponent = true;
      allDirectiveDefs.push(def);
    }
  }
  for (let i = hasComponent ? 1 : 0; i < matches.length; i++) {
    allDirectiveDefs.push(matches[i]);
  }
  if (hostDirectiveDefs !== null) {
    hostDirectiveDefs.forEach((def, hostDirectiveDef) => {
      patchDeclaredInputs(hostDirectiveDef.declaredInputs, def.inputs);
    });
  }
  return [allDirectiveDefs, hostDirectiveDefs, hostDirectiveRanges];
}
function findHostDirectiveDefs(currentDef, matchedDefs, hostDirectiveDefs, templateMatches) {
  if (currentDef.hostDirectives !== null) {
    for (const configOrFn of currentDef.hostDirectives) {
      if (typeof configOrFn === 'function') {
        const resolved = configOrFn();
        for (const config of resolved) {
          trackHostDirectiveDef(createHostDirectiveDef(config), matchedDefs, hostDirectiveDefs, templateMatches);
        }
      } else {
        trackHostDirectiveDef(configOrFn, matchedDefs, hostDirectiveDefs, templateMatches);
      }
    }
  }
}
function trackHostDirectiveDef(def, finalMatches, hostDirectiveDefs, templateMatches) {
  const hostDirectiveDef = getDirectiveDef(def.directive);
  if (typeof ngDevMode === 'undefined' || ngDevMode) {
    validateHostDirective(def, hostDirectiveDef);
  }
  findHostDirectiveDefs(hostDirectiveDef, finalMatches, hostDirectiveDefs, templateMatches);
  if (hostDirectiveDefs.has(hostDirectiveDef)) {
    const existing = hostDirectiveDefs.get(hostDirectiveDef);
    mergeBindingMaps(existing, def.inputs, 'input');
    mergeBindingMaps(existing, def.outputs, 'output');
  } else if (!templateMatches.includes(hostDirectiveDef)) {
    hostDirectiveDefs.set(hostDirectiveDef, def);
    finalMatches.push(hostDirectiveDef);
  }
}
function mergeBindingMaps(existingDef, newMap, kind) {
  const targetMap = kind === 'input' ? existingDef.inputs : existingDef.outputs;
  Object.keys(newMap).forEach(publicName => {
    const alias = newMap[publicName];
    if (!Object.hasOwn(targetMap, publicName) || targetMap[publicName] === alias) {
      targetMap[publicName] = alias;
    } else if (typeof ngDevMode === 'undefined' || ngDevMode) {
      const message = `${kind === 'input' ? 'Input' : 'Output'} "${publicName}" from ${existingDef.directive.name} ` + `is exposed under the following conflicting names: "${targetMap[publicName]}" and "${alias}". ` + `An ${kind} can only be exposed under a single name.`;
      throw new RuntimeError(312, message);
    }
  });
}
function createHostDirectiveDef(config) {
  return typeof config === 'function' ? {
    directive: resolveForwardRef(config),
    inputs: {},
    outputs: {}
  } : {
    directive: resolveForwardRef(config.directive),
    inputs: bindingArrayToMap(config.inputs),
    outputs: bindingArrayToMap(config.outputs)
  };
}
function bindingArrayToMap(bindings) {
  const result = {};
  if (bindings !== undefined && bindings.length > 0) {
    for (let i = 0; i < bindings.length; i += 2) {
      result[bindings[i]] = bindings[i + 1];
    }
  }
  return result;
}
function patchDeclaredInputs(declaredInputs, exposedInputs) {
  for (const publicName in exposedInputs) {
    if (Object.hasOwn(exposedInputs, publicName)) {
      const remappedPublicName = exposedInputs[publicName];
      const privateName = declaredInputs[publicName];
      if ((typeof ngDevMode === 'undefined' || ngDevMode) && Object.hasOwn(declaredInputs, remappedPublicName)) {
        assertEqual(declaredInputs[remappedPublicName], declaredInputs[publicName], `Conflicting host directive input alias ${publicName}.`);
      }
      declaredInputs[remappedPublicName] = privateName;
    }
  }
}
function validateHostDirective(hostDirectiveConfig, directiveDef) {
  const type = hostDirectiveConfig.directive;
  if (directiveDef === null) {
    if (getComponentDef(type) !== null) {
      throw new RuntimeError(310, `Host directive ${type.name} cannot be a component.`);
    }
    throw new RuntimeError(307, `Could not resolve metadata for host directive ${type.name}. ` + `Make sure that the ${type.name} class is annotated with an @Directive decorator.`);
  }
  if (!directiveDef.standalone) {
    throw new RuntimeError(308, `Host directive ${directiveDef.type.name} must be standalone.`);
  }
  validateMappings('input', directiveDef, hostDirectiveConfig.inputs);
  validateMappings('output', directiveDef, hostDirectiveConfig.outputs);
}
function validateMappings(bindingType, def, hostDirectiveBindings) {
  const className = def.type.name;
  const bindings = bindingType === 'input' ? def.inputs : def.outputs;
  for (const publicName in hostDirectiveBindings) {
    if (Object.hasOwn(hostDirectiveBindings, publicName)) {
      if (!Object.hasOwn(bindings, publicName)) {
        throw new RuntimeError(311, `Directive ${className} does not have an ${bindingType} with a public name of ${publicName}.`);
      }
      const remappedPublicName = hostDirectiveBindings[publicName];
      if (Object.hasOwn(bindings, remappedPublicName) && remappedPublicName !== publicName) {
        throw new RuntimeError(312, `Cannot alias ${bindingType} ${publicName} of host directive ${className} to ${remappedPublicName}, because it already has a different ${bindingType} with the same public name.`);
      }
    }
  }
}

function getSuperType(type) {
  return Object.getPrototypeOf(type.prototype).constructor;
}
function ɵɵInheritDefinitionFeature(definition) {
  let superType = getSuperType(definition.type);
  let shouldInheritFields = true;
  const inheritanceChain = [definition];
  while (superType && superType !== Function.prototype && superType !== Object.prototype) {
    let superDef = undefined;
    const cmpDef = Object.hasOwn(superType, NG_COMP_DEF) ? superType[NG_COMP_DEF] : undefined;
    const dirDef = Object.hasOwn(superType, NG_DIR_DEF) ? superType[NG_DIR_DEF] : undefined;
    if (isComponentDef(definition)) {
      superDef = cmpDef ?? dirDef;
    } else {
      if (cmpDef) {
        throw new RuntimeError(903, ngDevMode && `Directives cannot inherit Components. Directive ${stringifyForError(definition.type)} is attempting to extend component ${stringifyForError(superType)}`);
      }
      superDef = dirDef;
    }
    if (superDef) {
      if (shouldInheritFields) {
        inheritanceChain.push(superDef);
        const writeableDef = definition;
        writeableDef.inputs = maybeUnwrapEmpty(definition.inputs);
        writeableDef.declaredInputs = maybeUnwrapEmpty(definition.declaredInputs);
        writeableDef.outputs = maybeUnwrapEmpty(definition.outputs);
        const superHostBindings = superDef.hostBindings;
        superHostBindings && inheritHostBindings(definition, superHostBindings);
        const superViewQuery = superDef.viewQuery;
        const superContentQueries = superDef.contentQueries;
        superViewQuery && inheritViewQuery(definition, superViewQuery);
        superContentQueries && inheritContentQueries(definition, superContentQueries);
        mergeInputsWithTransforms(definition, superDef);
        fillProperties(definition.outputs, superDef.outputs);
        if (isComponentDef(superDef) && superDef.data.animation) {
          const defData = definition.data;
          defData.animation = (defData.animation || []).concat(superDef.data.animation);
        }
      }
      const features = superDef.features;
      if (features) {
        for (let i = 0; i < features.length; i++) {
          const feature = features[i];
          if (feature && feature.ngInherit) {
            feature(definition);
          }
          if (feature === ɵɵInheritDefinitionFeature) {
            shouldInheritFields = false;
          }
        }
      }
    }
    superType = Object.getPrototypeOf(superType);
  }
  mergeHostAttrsAcrossInheritance(inheritanceChain);
}
function mergeInputsWithTransforms(target, source) {
  for (const key in source.inputs) {
    if (!Object.hasOwn(source.inputs, key)) {
      continue;
    }
    if (Object.hasOwn(target.inputs, key)) {
      continue;
    }
    const value = source.inputs[key];
    if (value !== undefined) {
      target.inputs[key] = value;
      target.declaredInputs[key] = source.declaredInputs[key];
    }
  }
}
function mergeHostAttrsAcrossInheritance(inheritanceChain) {
  let hostVars = 0;
  let hostAttrs = null;
  for (let i = inheritanceChain.length - 1; i >= 0; i--) {
    const def = inheritanceChain[i];
    def.hostVars = hostVars += def.hostVars;
    def.hostAttrs = mergeHostAttrs(def.hostAttrs, hostAttrs = mergeHostAttrs(hostAttrs, def.hostAttrs));
  }
}
function maybeUnwrapEmpty(value) {
  if (value === EMPTY_OBJ) {
    return {};
  } else if (value === EMPTY_ARRAY) {
    return [];
  } else {
    return value;
  }
}
function inheritViewQuery(definition, superViewQuery) {
  const prevViewQuery = definition.viewQuery;
  if (prevViewQuery) {
    definition.viewQuery = (rf, ctx) => {
      superViewQuery(rf, ctx);
      prevViewQuery(rf, ctx);
    };
  } else {
    definition.viewQuery = superViewQuery;
  }
}
function inheritContentQueries(definition, superContentQueries) {
  const prevContentQueries = definition.contentQueries;
  if (prevContentQueries) {
    definition.contentQueries = (rf, ctx, directiveIndex) => {
      superContentQueries(rf, ctx, directiveIndex);
      prevContentQueries(rf, ctx, directiveIndex);
    };
  } else {
    definition.contentQueries = superContentQueries;
  }
}
function inheritHostBindings(definition, superHostBindings) {
  const prevHostBindings = definition.hostBindings;
  if (prevHostBindings) {
    definition.hostBindings = (rf, ctx) => {
      superHostBindings(rf, ctx);
      prevHostBindings(rf, ctx);
    };
  } else {
    definition.hostBindings = superHostBindings;
  }
}

function templateCreate(tNode, declarationLView, declarationTView, index, templateFn, decls, vars, flags) {
  if (declarationTView.firstCreatePass) {
    tNode.mergedAttrs = mergeHostAttrs(tNode.mergedAttrs, tNode.attrs);
    const embeddedTView = tNode.tView = createTView(2, tNode, templateFn, decls, vars, declarationTView.directiveRegistry, declarationTView.pipeRegistry, null, declarationTView.schemas, declarationTView.consts, null);
    if (declarationTView.queries !== null) {
      declarationTView.queries.template(declarationTView, tNode);
      embeddedTView.queries = declarationTView.queries.embeddedTView(tNode);
    }
  }
  if (flags) {
    tNode.flags |= flags;
  }
  setCurrentTNode(tNode, false);
  const comment = _locateOrCreateContainerAnchor(declarationTView, declarationLView, tNode, index);
  if (wasLastNodeCreated()) {
    appendChild(declarationTView, declarationLView, comment, tNode);
  }
  attachPatchData(comment, declarationLView);
  const lContainer = createLContainer(comment, declarationLView, comment, tNode);
  declarationLView[index + HEADER_OFFSET] = lContainer;
  addToEndOfViewTree(declarationLView, lContainer);
  populateDehydratedViewsInLContainer(lContainer, tNode, declarationLView);
}
function declareDirectiveHostTemplate(declarationLView, declarationTView, index, templateFn, decls, vars, tagName, attrs, flags, localRefsIndex, localRefExtractor) {
  const adjustedIndex = index + HEADER_OFFSET;
  let tNode;
  if (declarationTView.firstCreatePass) {
    tNode = getOrCreateTNode(declarationTView, adjustedIndex, 4, tagName || null, attrs || null);
    if (getBindingsEnabled()) {
      resolveDirectives(declarationTView, declarationLView, tNode, getConstant(declarationTView.consts, localRefsIndex), findDirectiveDefMatches);
    }
    registerPostOrderHooks(declarationTView, tNode);
  } else {
    tNode = declarationTView.data[adjustedIndex];
  }
  templateCreate(tNode, declarationLView, declarationTView, index, templateFn, decls, vars, flags);
  if (isDirectiveHost(tNode)) {
    createDirectivesInstances(declarationTView, declarationLView, tNode);
  }
  if (localRefsIndex != null) {
    saveResolvedLocalsInData(declarationLView, tNode, localRefExtractor);
  }
  return tNode;
}
function declareNoDirectiveHostTemplate(declarationLView, declarationTView, index, templateFn, decls, vars, tagName, attrs, flags, localRefsIndex, localRefExtractor) {
  const adjustedIndex = index + HEADER_OFFSET;
  let tNode;
  if (declarationTView.firstCreatePass) {
    tNode = getOrCreateTNode(declarationTView, adjustedIndex, 4, tagName || null, attrs || null);
    if (localRefsIndex != null) {
      const refs = getConstant(declarationTView.consts, localRefsIndex);
      tNode.localNames = [];
      for (let i = 0; i < refs.length; i += 2) {
        tNode.localNames.push(refs[i], -1);
      }
    }
  } else {
    tNode = declarationTView.data[adjustedIndex];
  }
  templateCreate(tNode, declarationLView, declarationTView, index, templateFn, decls, vars, flags);
  if (localRefsIndex != null) {
    saveResolvedLocalsInData(declarationLView, tNode, localRefExtractor);
  }
  return tNode;
}
function ɵɵtemplate(index, templateFn, decls, vars, tagName, attrsIndex, localRefsIndex, localRefExtractor) {
  const lView = getLView();
  const tView = getTView();
  const attrs = getConstant(tView.consts, attrsIndex);
  declareDirectiveHostTemplate(lView, tView, index, templateFn, decls, vars, tagName, attrs, undefined, localRefsIndex, localRefExtractor);
  return ɵɵtemplate;
}
function ɵɵdomTemplate(index, templateFn, decls, vars, tagName, attrsIndex, localRefsIndex, localRefExtractor) {
  const lView = getLView();
  const tView = getTView();
  const attrs = getConstant(tView.consts, attrsIndex);
  declareNoDirectiveHostTemplate(lView, tView, index, templateFn, decls, vars, tagName, attrs, undefined, localRefsIndex, localRefExtractor);
  return ɵɵdomTemplate;
}
let _locateOrCreateContainerAnchor = createContainerAnchorImpl;
function createContainerAnchorImpl(tView, lView, tNode, index) {
  lastNodeWasCreated(true);
  return lView[RENDERER].createComment(ngDevMode ? 'container' : '');
}
function locateOrCreateContainerAnchorImpl(tView, lView, tNode, index) {
  const isNodeCreationMode = !canHydrateNode(lView, tNode);
  lastNodeWasCreated(isNodeCreationMode);
  const ssrId = lView[HYDRATION]?.data[TEMPLATES]?.[index] ?? null;
  if (ssrId !== null && tNode.tView !== null) {
    if (tNode.tView.ssrId === null) {
      tNode.tView.ssrId = ssrId;
    } else {
      ngDevMode && assertEqual(tNode.tView.ssrId, ssrId, 'Unexpected value of the `ssrId` for this TView');
    }
  }
  if (isNodeCreationMode) {
    return createContainerAnchorImpl(tView, lView);
  }
  const hydrationInfo = lView[HYDRATION];
  const currentRNode = locateNextRNode(hydrationInfo, tView, lView, tNode);
  ngDevMode && validateNodeExists(currentRNode, lView, tNode);
  setSegmentHead(hydrationInfo, index, currentRNode);
  const viewContainerSize = calcSerializedContainerSize(hydrationInfo, index);
  const comment = siblingAfter(viewContainerSize, currentRNode);
  if (ngDevMode) {
    validateMatchingNode(comment, Node.COMMENT_NODE, null, lView, tNode);
    markRNodeAsClaimedByHydration(comment);
  }
  return comment;
}
function enableLocateOrCreateContainerAnchorImpl() {
  _locateOrCreateContainerAnchor = locateOrCreateContainerAnchorImpl;
}

var DeferDependenciesLoadingState;
(function (DeferDependenciesLoadingState) {
  DeferDependenciesLoadingState[DeferDependenciesLoadingState["NOT_STARTED"] = 0] = "NOT_STARTED";
  DeferDependenciesLoadingState[DeferDependenciesLoadingState["IN_PROGRESS"] = 1] = "IN_PROGRESS";
  DeferDependenciesLoadingState[DeferDependenciesLoadingState["COMPLETE"] = 2] = "COMPLETE";
  DeferDependenciesLoadingState[DeferDependenciesLoadingState["FAILED"] = 3] = "FAILED";
})(DeferDependenciesLoadingState || (DeferDependenciesLoadingState = {}));
const MINIMUM_SLOT = 0;
const LOADING_AFTER_SLOT = 1;
var DeferBlockState;
(function (DeferBlockState) {
  DeferBlockState[DeferBlockState["Placeholder"] = 0] = "Placeholder";
  DeferBlockState[DeferBlockState["Loading"] = 1] = "Loading";
  DeferBlockState[DeferBlockState["Complete"] = 2] = "Complete";
  DeferBlockState[DeferBlockState["Error"] = 3] = "Error";
})(DeferBlockState || (DeferBlockState = {}));
var DeferBlockInternalState;
(function (DeferBlockInternalState) {
  DeferBlockInternalState[DeferBlockInternalState["Initial"] = -1] = "Initial";
})(DeferBlockInternalState || (DeferBlockInternalState = {}));
const NEXT_DEFER_BLOCK_STATE = 0;
const DEFER_BLOCK_STATE = 1;
const STATE_IS_FROZEN_UNTIL = 2;
const LOADING_AFTER_CLEANUP_FN = 3;
const TRIGGER_CLEANUP_FNS = 4;
const PREFETCH_TRIGGER_CLEANUP_FNS = 5;
const SSR_UNIQUE_ID = 6;
const SSR_BLOCK_STATE = 7;
const ON_COMPLETE_FNS = 8;
const HYDRATE_TRIGGER_CLEANUP_FNS = 9;
var DeferBlockBehavior;
(function (DeferBlockBehavior) {
  DeferBlockBehavior[DeferBlockBehavior["Manual"] = 0] = "Manual";
  DeferBlockBehavior[DeferBlockBehavior["Playthrough"] = 1] = "Playthrough";
})(DeferBlockBehavior || (DeferBlockBehavior = {}));

function storeTriggerCleanupFn(type, lDetails, cleanupFn) {
  const key = getCleanupFnKeyByType(type);
  if (lDetails[key] === null) {
    lDetails[key] = [];
  }
  lDetails[key].push(cleanupFn);
}
function invokeTriggerCleanupFns(type, lDetails) {
  const key = getCleanupFnKeyByType(type);
  const cleanupFns = lDetails[key];
  if (cleanupFns !== null) {
    for (const cleanupFn of cleanupFns) {
      cleanupFn();
    }
    lDetails[key] = null;
  }
}
function invokeAllTriggerCleanupFns(lDetails) {
  invokeTriggerCleanupFns(1, lDetails);
  invokeTriggerCleanupFns(0, lDetails);
  invokeTriggerCleanupFns(2, lDetails);
}
function getCleanupFnKeyByType(type) {
  let key = TRIGGER_CLEANUP_FNS;
  if (type === 1) {
    key = PREFETCH_TRIGGER_CLEANUP_FNS;
  } else if (type === 2) {
    key = HYDRATE_TRIGGER_CLEANUP_FNS;
  }
  return key;
}

function getDeferBlockDataIndex(deferBlockIndex) {
  return deferBlockIndex + 1;
}
function getLDeferBlockDetails(lView, tNode) {
  const tView = lView[TVIEW$1];
  const slotIndex = getDeferBlockDataIndex(tNode.index);
  ngDevMode && assertIndexInDeclRange(tView, slotIndex);
  return lView[slotIndex];
}
function setLDeferBlockDetails(lView, deferBlockIndex, lDetails) {
  const tView = lView[TVIEW$1];
  const slotIndex = getDeferBlockDataIndex(deferBlockIndex);
  ngDevMode && assertIndexInDeclRange(tView, slotIndex);
  lView[slotIndex] = lDetails;
}
function getTDeferBlockDetails(tView, tNode) {
  const slotIndex = getDeferBlockDataIndex(tNode.index);
  ngDevMode && assertIndexInDeclRange(tView, slotIndex);
  return tView.data[slotIndex];
}
function setTDeferBlockDetails(tView, deferBlockIndex, deferBlockConfig) {
  const slotIndex = getDeferBlockDataIndex(deferBlockIndex);
  ngDevMode && assertIndexInDeclRange(tView, slotIndex);
  tView.data[slotIndex] = deferBlockConfig;
}
function getTemplateIndexForState(newState, hostLView, tNode) {
  const tView = hostLView[TVIEW$1];
  const tDetails = getTDeferBlockDetails(tView, tNode);
  switch (newState) {
    case DeferBlockState.Complete:
      return tDetails.primaryTmplIndex;
    case DeferBlockState.Loading:
      return tDetails.loadingTmplIndex;
    case DeferBlockState.Error:
      return tDetails.errorTmplIndex;
    case DeferBlockState.Placeholder:
      return tDetails.placeholderTmplIndex;
    default:
      ngDevMode && throwError(`Unexpected defer block state: ${newState}`);
      return null;
  }
}
function getMinimumDurationForState(tDetails, currentState) {
  if (currentState === DeferBlockState.Placeholder) {
    return tDetails.placeholderBlockConfig?.[MINIMUM_SLOT] ?? null;
  } else if (currentState === DeferBlockState.Loading) {
    return tDetails.loadingBlockConfig?.[MINIMUM_SLOT] ?? null;
  }
  return null;
}
function getLoadingBlockAfter(tDetails) {
  return tDetails.loadingBlockConfig?.[LOADING_AFTER_SLOT] ?? null;
}
function addDepsToRegistry(currentDeps, newDeps) {
  if (!currentDeps || currentDeps.length === 0) {
    return newDeps;
  }
  const currentDepSet = new Set(currentDeps);
  for (const dep of newDeps) {
    currentDepSet.add(dep);
  }
  return currentDeps.length === currentDepSet.size ? currentDeps : Array.from(currentDepSet);
}
function getPrimaryBlockTNode(tView, tDetails) {
  const adjustedIndex = tDetails.primaryTmplIndex + HEADER_OFFSET;
  return getTNode(tView, adjustedIndex);
}
function assertDeferredDependenciesLoaded(tDetails) {
  assertEqual(tDetails.loadingState, DeferDependenciesLoadingState.COMPLETE, 'Expecting all deferred dependencies to be loaded.');
}
function isTDeferBlockDetails(value) {
  return value !== null && typeof value === 'object' && typeof value.primaryTmplIndex === 'number';
}
function isDeferBlock(tView, tNode) {
  let tDetails = null;
  const slotIndex = getDeferBlockDataIndex(tNode.index);
  if (HEADER_OFFSET < slotIndex && slotIndex < tView.bindingStartIndex) {
    tDetails = getTDeferBlockDetails(tView, tNode);
  }
  return !!tDetails && isTDeferBlockDetails(tDetails);
}
function trackTriggerForDebugging(tView, tNode, textRepresentation) {
  const tDetails = getTDeferBlockDetails(tView, tNode);
  tDetails.debug ??= {};
  tDetails.debug.triggers ??= new Set();
  tDetails.debug.triggers.add(textRepresentation);
}

class CachedInjectorService {
  cachedInjectors = new Map();
  getOrCreateInjector(key, parentInjector, providers, debugName) {
    if (!this.cachedInjectors.has(key)) {
      const injector = providers.length > 0 ? createEnvironmentInjector(providers, parentInjector, debugName) : null;
      this.cachedInjectors.set(key, injector);
    }
    return this.cachedInjectors.get(key);
  }
  ngOnDestroy() {
    try {
      for (const injector of this.cachedInjectors.values()) {
        if (injector !== null) {
          injector.destroy();
        }
      }
    } finally {
      this.cachedInjectors.clear();
    }
  }
  static ɵprov =
  /* @__PURE__ */
  __defineInjectable({
    token: CachedInjectorService,
    providedIn: 'environment',
    factory: () => new CachedInjectorService()
  });
}

function onTimer(delay) {
  return (callback, injector) => scheduleTimerTrigger(delay, callback, injector);
}
function scheduleTimerTrigger(delay, callback, injector) {
  const scheduler = injector.get(TimerScheduler);
  const ngZone = injector.get(NgZone);
  const cleanupFn = () => scheduler.remove(callback);
  scheduler.add(delay, callback, ngZone);
  return cleanupFn;
}
class TimerScheduler {
  executingCallbacks = false;
  timeoutId = null;
  invokeTimerAt = null;
  current = [];
  deferred = [];
  add(delay, callback, ngZone) {
    const target = this.executingCallbacks ? this.deferred : this.current;
    this.addToQueue(target, Date.now() + delay, callback);
    this.scheduleTimer(ngZone);
  }
  remove(callback) {
    const {
      current,
      deferred
    } = this;
    const callbackIndex = this.removeFromQueue(current, callback);
    if (callbackIndex === -1) {
      this.removeFromQueue(deferred, callback);
    }
    if (current.length === 0 && deferred.length === 0) {
      this.clearTimeout();
    }
  }
  addToQueue(target, invokeAt, callback) {
    let insertAtIndex = target.length;
    for (let i = 0; i < target.length; i += 2) {
      const invokeQueuedCallbackAt = target[i];
      if (invokeQueuedCallbackAt > invokeAt) {
        insertAtIndex = i;
        break;
      }
    }
    arrayInsert2(target, insertAtIndex, invokeAt, callback);
  }
  removeFromQueue(target, callback) {
    let index = -1;
    for (let i = 0; i < target.length; i += 2) {
      const queuedCallback = target[i + 1];
      if (queuedCallback === callback) {
        index = i;
        break;
      }
    }
    if (index > -1) {
      arraySplice(target, index, 2);
    }
    return index;
  }
  scheduleTimer(ngZone) {
    const callback = () => {
      this.clearTimeout();
      this.executingCallbacks = true;
      const current = [...this.current];
      const now = Date.now();
      for (let i = 0; i < current.length; i += 2) {
        const invokeAt = current[i];
        const callback = current[i + 1];
        if (invokeAt <= now) {
          callback();
        } else {
          break;
        }
      }
      let lastCallbackIndex = -1;
      for (let i = 0; i < this.current.length; i += 2) {
        const invokeAt = this.current[i];
        if (invokeAt <= now) {
          lastCallbackIndex = i + 1;
        } else {
          break;
        }
      }
      if (lastCallbackIndex >= 0) {
        arraySplice(this.current, 0, lastCallbackIndex + 1);
      }
      this.executingCallbacks = false;
      if (this.deferred.length > 0) {
        for (let i = 0; i < this.deferred.length; i += 2) {
          const invokeAt = this.deferred[i];
          const callback = this.deferred[i + 1];
          this.addToQueue(this.current, invokeAt, callback);
        }
        this.deferred.length = 0;
      }
      this.scheduleTimer(ngZone);
    };
    const FRAME_DURATION_MS = 16;
    if (this.current.length > 0) {
      const now = Date.now();
      const invokeAt = this.current[0];
      if (this.timeoutId === null || this.invokeTimerAt && this.invokeTimerAt - invokeAt > FRAME_DURATION_MS) {
        this.clearTimeout();
        const timeout = Math.max(invokeAt - now, FRAME_DURATION_MS);
        this.invokeTimerAt = invokeAt;
        this.timeoutId = ngZone.runOutsideAngular(() => {
          return setTimeout(() => ngZone.run(callback), timeout);
        });
      }
    }
  }
  clearTimeout() {
    if (this.timeoutId !== null) {
      clearTimeout(this.timeoutId);
      this.timeoutId = null;
    }
  }
  ngOnDestroy() {
    this.clearTimeout();
    this.current.length = 0;
    this.deferred.length = 0;
  }
  static ɵprov =
  /* @__PURE__ */
  __defineInjectable({
    token: TimerScheduler,
    providedIn: 'root',
    factory: () => new TimerScheduler()
  });
}

const DEFER_BLOCK_DEPENDENCY_INTERCEPTOR = /* @__PURE__ */new InjectionToken('DEFER_BLOCK_DEPENDENCY_INTERCEPTOR');
const DEFER_BLOCK_CONFIG = new InjectionToken(typeof ngDevMode !== 'undefined' && ngDevMode ? 'DEFER_BLOCK_CONFIG' : '');
function getOrCreateEnvironmentInjector(parentInjector, tDetails, providers) {
  return parentInjector.get(CachedInjectorService).getOrCreateInjector(tDetails, parentInjector, providers, ngDevMode ? 'DeferBlock Injector' : '');
}
function createDeferBlockInjector(parentInjector, tDetails, providers) {
  if (parentInjector instanceof ChainedInjector) {
    const origInjector = parentInjector.injector;
    const parentEnvInjector = parentInjector.parentInjector;
    const envInjector = getOrCreateEnvironmentInjector(parentEnvInjector, tDetails, providers);
    return new ChainedInjector(origInjector, envInjector);
  }
  const parentEnvInjector = parentInjector.get(EnvironmentInjector);
  if (parentEnvInjector !== parentInjector) {
    const envInjector = getOrCreateEnvironmentInjector(parentEnvInjector, tDetails, providers);
    return new ChainedInjector(parentInjector, envInjector);
  }
  return getOrCreateEnvironmentInjector(parentInjector, tDetails, providers);
}
function renderDeferBlockState(newState, tNode, lContainer, skipTimerScheduling = false) {
  const hostLView = lContainer[PARENT];
  const hostTView = hostLView[TVIEW$1];
  if (isDestroyed(hostLView)) return;
  ngDevMode && assertTNodeForLView(tNode, hostLView);
  const lDetails = getLDeferBlockDetails(hostLView, tNode);
  ngDevMode && assertDefined(lDetails, 'Expected a defer block state defined');
  const currentState = lDetails[DEFER_BLOCK_STATE];
  const ssrState = lDetails[SSR_BLOCK_STATE];
  if (ssrState !== null && newState < ssrState) {
    return;
  }
  if (isValidStateChange(currentState, newState) && isValidStateChange(lDetails[NEXT_DEFER_BLOCK_STATE] ?? -1, newState)) {
    const tDetails = getTDeferBlockDetails(hostTView, tNode);
    const needsScheduling = !skipTimerScheduling && (typeof ngServerMode === 'undefined' || !ngServerMode) && (getLoadingBlockAfter(tDetails) !== null || getMinimumDurationForState(tDetails, DeferBlockState.Loading) !== null || getMinimumDurationForState(tDetails, DeferBlockState.Placeholder));
    if (ngDevMode && needsScheduling) {
      assertDefined(applyDeferBlockStateWithSchedulingImpl, 'Expected scheduling function to be defined');
    }
    const applyStateFn = needsScheduling ? applyDeferBlockStateWithSchedulingImpl : applyDeferBlockState;
    try {
      applyStateFn(newState, lDetails, lContainer, tNode, hostLView);
    } catch (error) {
      handleUncaughtError(hostLView, error);
    }
  }
}
function findMatchingDehydratedViewForDeferBlock(lContainer, lDetails) {
  const dehydratedViewIx = lContainer[DEHYDRATED_VIEWS]?.findIndex(view => view.data[DEFER_BLOCK_STATE$1] === lDetails[DEFER_BLOCK_STATE]) ?? -1;
  const dehydratedView = dehydratedViewIx > -1 ? lContainer[DEHYDRATED_VIEWS][dehydratedViewIx] : null;
  return {
    dehydratedView,
    dehydratedViewIx
  };
}
function applyDeferBlockState(newState, lDetails, lContainer, tNode, hostLView) {
  profiler(ProfilerEvent.DeferBlockStateStart);
  const stateTmplIndex = getTemplateIndexForState(newState, hostLView, tNode);
  if (stateTmplIndex !== null) {
    lDetails[DEFER_BLOCK_STATE] = newState;
    const hostTView = hostLView[TVIEW$1];
    const adjustedIndex = stateTmplIndex + HEADER_OFFSET;
    const activeBlockTNode = getTNode(hostTView, adjustedIndex);
    const viewIndex = 0;
    removeLViewFromLContainer(lContainer, viewIndex);
    let injector;
    if (newState === DeferBlockState.Complete) {
      const tDetails = getTDeferBlockDetails(hostTView, tNode);
      const providers = tDetails.providers;
      if (providers && providers.length > 0) {
        injector = createDeferBlockInjector(hostLView[INJECTOR], tDetails, providers);
      }
    }
    const {
      dehydratedView,
      dehydratedViewIx
    } = findMatchingDehydratedViewForDeferBlock(lContainer, lDetails);
    const embeddedLView = createAndRenderEmbeddedLView(hostLView, activeBlockTNode, null, {
      injector,
      dehydratedView
    });
    addLViewToLContainer(lContainer, embeddedLView, viewIndex, shouldAddViewToDom(activeBlockTNode, dehydratedView));
    markViewForRefresh(embeddedLView);
    if (dehydratedViewIx > -1) {
      lContainer[DEHYDRATED_VIEWS]?.splice(dehydratedViewIx, 1);
    }
    if ((newState === DeferBlockState.Complete || newState === DeferBlockState.Error) && Array.isArray(lDetails[ON_COMPLETE_FNS])) {
      for (const callback of lDetails[ON_COMPLETE_FNS]) {
        callback();
      }
      lDetails[ON_COMPLETE_FNS] = null;
    }
  }
  profiler(ProfilerEvent.DeferBlockStateEnd);
}
function applyDeferBlockStateWithScheduling(newState, lDetails, lContainer, tNode, hostLView) {
  const now = Date.now();
  const hostTView = hostLView[TVIEW$1];
  const tDetails = getTDeferBlockDetails(hostTView, tNode);
  if (lDetails[STATE_IS_FROZEN_UNTIL] === null || lDetails[STATE_IS_FROZEN_UNTIL] <= now) {
    lDetails[STATE_IS_FROZEN_UNTIL] = null;
    const loadingAfter = getLoadingBlockAfter(tDetails);
    const inLoadingAfterPhase = lDetails[LOADING_AFTER_CLEANUP_FN] !== null;
    if (newState === DeferBlockState.Loading && loadingAfter !== null && !inLoadingAfterPhase) {
      lDetails[NEXT_DEFER_BLOCK_STATE] = newState;
      const cleanupFn = scheduleDeferBlockUpdate(loadingAfter, lDetails, tNode, lContainer, hostLView);
      lDetails[LOADING_AFTER_CLEANUP_FN] = cleanupFn;
    } else {
      if (newState > DeferBlockState.Loading && inLoadingAfterPhase) {
        lDetails[LOADING_AFTER_CLEANUP_FN]();
        lDetails[LOADING_AFTER_CLEANUP_FN] = null;
        lDetails[NEXT_DEFER_BLOCK_STATE] = null;
      }
      applyDeferBlockState(newState, lDetails, lContainer, tNode, hostLView);
      const duration = getMinimumDurationForState(tDetails, newState);
      if (duration !== null) {
        lDetails[STATE_IS_FROZEN_UNTIL] = now + duration;
        scheduleDeferBlockUpdate(duration, lDetails, tNode, lContainer, hostLView);
      }
    }
  } else {
    lDetails[NEXT_DEFER_BLOCK_STATE] = newState;
  }
}
function scheduleDeferBlockUpdate(timeout, lDetails, tNode, lContainer, hostLView) {
  const callback = () => {
    const nextState = lDetails[NEXT_DEFER_BLOCK_STATE];
    lDetails[STATE_IS_FROZEN_UNTIL] = null;
    lDetails[NEXT_DEFER_BLOCK_STATE] = null;
    if (nextState !== null) {
      renderDeferBlockState(nextState, tNode, lContainer);
    }
  };
  return scheduleTimerTrigger(timeout, callback, hostLView[INJECTOR]);
}
function isValidStateChange(currentState, newState) {
  return currentState < newState;
}
function renderPlaceholder(lView, tNode) {
  const lContainer = lView[tNode.index];
  ngDevMode && assertLContainer(lContainer);
  renderDeferBlockState(DeferBlockState.Placeholder, tNode, lContainer);
}
function renderDeferStateAfterResourceLoading(tDetails, tNode, lContainer) {
  ngDevMode && assertDefined(tDetails.loadingPromise, 'Expected loading Promise to exist on this defer block');
  tDetails.loadingPromise.then(() => {
    if (tDetails.loadingState === DeferDependenciesLoadingState.COMPLETE) {
      ngDevMode && assertDeferredDependenciesLoaded(tDetails);
      renderDeferBlockState(DeferBlockState.Complete, tNode, lContainer);
    } else if (tDetails.loadingState === DeferDependenciesLoadingState.FAILED) {
      renderDeferBlockState(DeferBlockState.Error, tNode, lContainer);
    }
  });
}
let applyDeferBlockStateWithSchedulingImpl = null;
function ɵɵdeferEnableTimerScheduling(tView, tDetails, placeholderConfigIndex, loadingConfigIndex) {
  const tViewConsts = tView.consts;
  if (placeholderConfigIndex != null) {
    tDetails.placeholderBlockConfig = getConstant(tViewConsts, placeholderConfigIndex);
  }
  if (loadingConfigIndex != null) {
    tDetails.loadingBlockConfig = getConstant(tViewConsts, loadingConfigIndex);
  }
  if (applyDeferBlockStateWithSchedulingImpl === null) {
    applyDeferBlockStateWithSchedulingImpl = applyDeferBlockStateWithScheduling;
  }
}
function shouldTriggerDeferBlock(triggerType, lView) {
  if (triggerType === 0 && typeof ngServerMode !== 'undefined' && ngServerMode) {
    return false;
  }
  const injector = lView[INJECTOR];
  const config = injector.get(DEFER_BLOCK_CONFIG, null, {
    optional: true
  });
  if (config?.behavior === DeferBlockBehavior.Manual) {
    return false;
  }
  return true;
}

function onViewportWrapper(trigger, callback, injector, wrapperOptions) {
  const ngZone = injector.get(NgZone);
  return onViewport(trigger, () => ngZone.run(callback), options => ngZone.runOutsideAngular(() => createIntersectionObserver(options)), wrapperOptions);
}
function getTriggerLView(deferredHostLView, deferredTNode, walkUpTimes) {
  if (walkUpTimes == null) {
    return deferredHostLView;
  }
  if (walkUpTimes >= 0) {
    return walkUpViews(walkUpTimes, deferredHostLView);
  }
  const deferredContainer = deferredHostLView[deferredTNode.index];
  ngDevMode && assertLContainer(deferredContainer);
  const triggerLView = deferredContainer[CONTAINER_HEADER_OFFSET] ?? null;
  if (ngDevMode && triggerLView !== null) {
    const lDetails = getLDeferBlockDetails(deferredHostLView, deferredTNode);
    const renderedState = lDetails[DEFER_BLOCK_STATE];
    assertEqual(renderedState, DeferBlockState.Placeholder, 'Expected a placeholder to be rendered in this defer block.');
    assertLView(triggerLView);
  }
  return triggerLView;
}
function getTriggerElement(triggerLView, triggerIndex) {
  const element = getNativeByIndex(HEADER_OFFSET + triggerIndex, triggerLView);
  ngDevMode && assertElement(element);
  return element;
}
function registerDomTrigger(initialLView, tNode, triggerIndex, walkUpTimes, registerFn, callback, type, options) {
  if (!shouldTriggerDeferBlock(type, initialLView)) {
    return;
  }
  const injector = initialLView[INJECTOR];
  const zone = injector.get(NgZone);
  let poll;
  function pollDomTrigger() {
    if (isDestroyed(initialLView)) {
      poll.destroy();
      return;
    }
    const lDetails = getLDeferBlockDetails(initialLView, tNode);
    const renderedState = lDetails[DEFER_BLOCK_STATE];
    if (renderedState !== DeferBlockInternalState.Initial && renderedState !== DeferBlockState.Placeholder) {
      poll.destroy();
      return;
    }
    const triggerLView = getTriggerLView(initialLView, tNode, walkUpTimes);
    if (!triggerLView) {
      return;
    }
    poll.destroy();
    if (isDestroyed(triggerLView)) {
      return;
    }
    const element = getTriggerElement(triggerLView, triggerIndex);
    const cleanup = registerFn(element, () => {
      zone.run(() => {
        if (initialLView !== triggerLView) {
          removeLViewOnDestroy(triggerLView, cleanup);
        }
        callback();
      });
    }, injector, options);
    if (initialLView !== triggerLView) {
      storeLViewOnDestroy(triggerLView, cleanup);
    }
    storeTriggerCleanupFn(type, lDetails, cleanup);
  }
  poll = afterEveryRender({
    read: pollDomTrigger
  }, {
    injector
  });
}

class Console {
  log(message) {
    console.log(message);
  }
  warn(message) {
    console.warn(message);
  }
  static ɵfac = function Console_Factory(__ngFactoryType__) {
    return new (__ngFactoryType__ || Console)();
  };
  static ɵprov = /*@__PURE__*/__defineInjectable({
    token: Console,
    factory: Console.ɵfac,
    providedIn: 'platform'
  });
}
(() => {
  (typeof ngDevMode === "undefined" || ngDevMode) && setClassMetadata(Console, [{
    type: Injectable,
    args: [{
      providedIn: 'platform'
    }]
  }], null, null);
})();

class DIDebugData {
  resolverToTokenToDependencies = new WeakMap();
  resolverToProviders = new WeakMap();
  resolverToEffects = new WeakMap();
  standaloneInjectorToComponent = new WeakMap();
  reset() {
    this.resolverToTokenToDependencies = new WeakMap();
    this.resolverToProviders = new WeakMap();
    this.standaloneInjectorToComponent = new WeakMap();
  }
}
let frameworkDIDebugData = new DIDebugData();
function getFrameworkDIDebugData() {
  return frameworkDIDebugData;
}
function setupFrameworkInjectorProfiler() {
  frameworkDIDebugData.reset();
  setInjectorProfiler(injectorProfilerEventHandler);
}
function injectorProfilerEventHandler(injectorProfilerEvent) {
  const {
    context,
    type
  } = injectorProfilerEvent;
  if (type === 0) {
    handleInjectEvent(context, injectorProfilerEvent.service);
  } else if (type === 1) {
    handleInstanceCreatedByInjectorEvent(context, injectorProfilerEvent.instance);
  } else if (type === 2) {
    handleProviderConfiguredEvent(context, injectorProfilerEvent.providerRecord);
  } else if (type === 3) {
    handleEffectCreatedEvent(context, injectorProfilerEvent.effect);
  } else if (type === 4) {
    handleEffectCreatedEvent(context, injectorProfilerEvent.effectPhase);
  }
}
function handleEffectCreatedEvent(context, effect) {
  const diResolver = getDIResolver(context.injector);
  if (diResolver === null) {
    throwError('An EffectCreated event must be run within an injection context.');
  }
  const {
    resolverToEffects
  } = frameworkDIDebugData;
  const cleanupContainer = effect instanceof EffectRefImpl ? effect[SIGNAL] : effect.sequence;
  let trackedEffects = resolverToEffects.get(diResolver);
  if (!trackedEffects) {
    trackedEffects = [];
    resolverToEffects.set(diResolver, trackedEffects);
  }
  trackedEffects.push(effect);
  cleanupContainer.onDestroyFns ??= [];
  cleanupContainer.onDestroyFns.push(() => {
    const index = trackedEffects.indexOf(effect);
    if (index > -1) {
      trackedEffects.splice(index, 1);
    }
  });
}
function handleInjectEvent(context, data) {
  const diResolver = getDIResolver(context.injector);
  if (diResolver === null) {
    throwError('An Inject event must be run within an injection context.');
  }
  const diResolverToInstantiatedToken = frameworkDIDebugData.resolverToTokenToDependencies;
  if (!diResolverToInstantiatedToken.has(diResolver)) {
    diResolverToInstantiatedToken.set(diResolver, new WeakMap());
  }
  if (!canBeHeldWeakly(context.token)) {
    return;
  }
  const instantiatedTokenToDependencies = diResolverToInstantiatedToken.get(diResolver);
  if (!instantiatedTokenToDependencies.has(context.token)) {
    instantiatedTokenToDependencies.set(context.token, []);
  }
  const {
    token,
    value,
    flags
  } = data;
  assertDefined(context.token, 'Injector profiler context token is undefined.');
  const dependencies = instantiatedTokenToDependencies.get(context.token);
  assertDefined(dependencies, 'Could not resolve dependencies for token.');
  if (context.injector instanceof NodeInjector) {
    dependencies.push({
      token,
      value,
      flags,
      injectedIn: getNodeInjectorContext(context.injector)
    });
  } else {
    dependencies.push({
      token,
      value,
      flags
    });
  }
}
function getNodeInjectorContext(injector) {
  if (!(injector instanceof NodeInjector)) {
    throwError('getNodeInjectorContext must be called with a NodeInjector');
  }
  const lView = getNodeInjectorLView(injector);
  const tNode = getNodeInjectorTNode(injector);
  if (tNode === null) {
    return;
  }
  assertTNodeForLView(tNode, lView);
  return {
    lView,
    tNode
  };
}
function handleInstanceCreatedByInjectorEvent(context, data) {
  const {
    value
  } = data;
  if (data.value == null) {
    return;
  }
  if (getDIResolver(context.injector) === null) {
    throwError('An InjectorCreatedInstance event must be run within an injection context.');
  }
  let standaloneComponent = undefined;
  if (typeof value === 'object') {
    standaloneComponent = value?.constructor;
  }
  if (standaloneComponent == undefined || !isStandaloneComponent(standaloneComponent)) {
    return;
  }
  const environmentInjector = context.injector.get(EnvironmentInjector, null, {
    optional: true
  });
  if (environmentInjector === null) {
    return;
  }
  const {
    standaloneInjectorToComponent
  } = frameworkDIDebugData;
  if (standaloneInjectorToComponent.has(environmentInjector)) {
    return;
  }
  standaloneInjectorToComponent.set(environmentInjector, standaloneComponent);
}
function isStandaloneComponent(value) {
  const def = getComponentDef(value);
  return !!def?.standalone;
}
function handleProviderConfiguredEvent(context, data) {
  const {
    resolverToProviders
  } = frameworkDIDebugData;
  let diResolver;
  if (context?.injector instanceof NodeInjector) {
    diResolver = getNodeInjectorTNode(context.injector);
  } else {
    diResolver = context.injector;
  }
  if (diResolver === null) {
    throwError('A ProviderConfigured event must be run within an injection context.');
  }
  if (!resolverToProviders.has(diResolver)) {
    resolverToProviders.set(diResolver, []);
  }
  resolverToProviders.get(diResolver).push(data);
}
function getDIResolver(injector) {
  let diResolver = null;
  if (injector === undefined) {
    return diResolver;
  }
  if (injector instanceof NodeInjector) {
    diResolver = getNodeInjectorLView(injector);
  } else {
    diResolver = injector;
  }
  return diResolver;
}
function canBeHeldWeakly(value) {
  return value !== null && (typeof value === 'object' || typeof value === 'function' || typeof value === 'symbol');
}

function applyChanges(component) {
  ngDevMode && assertDefined(component, 'component');
  markViewDirty(getComponentViewByInstance(component), 3);
  getRootComponents(component).forEach(rootComponent => detectChanges(rootComponent));
}
function detectChanges(component) {
  const view = getComponentViewByInstance(component);
  view[FLAGS] |= 1024;
  detectChangesInternal(view);
}

var ControlFlowBlockType;
(function (ControlFlowBlockType) {
  ControlFlowBlockType[ControlFlowBlockType["Defer"] = 0] = "Defer";
  ControlFlowBlockType[ControlFlowBlockType["For"] = 1] = "For";
})(ControlFlowBlockType || (ControlFlowBlockType = {}));

function getControlFlowBlocks(node) {
  const lView = getLContext(node)?.lView;
  if (lView) {
    return findControlFlowBlocks(node, lView);
  }
  return [];
}
const deferBlockFinder = ({
  node,
  lView,
  tView,
  slotIdx
}) => {
  const slot = lView[slotIdx];
  if (!isLContainer(slot)) {
    return null;
  }
  const lContainer = slot;
  const isLast = slotIdx === tView.bindingStartIndex - 1;
  if (!isLast) {
    const tNode = tView.data[slotIdx];
    const tDetails = getTDeferBlockDetails(tView, tNode);
    if (isTDeferBlockDetails(tDetails)) {
      const native = getNativeByTNode(tNode, lView);
      const lDetails = getLDeferBlockDetails(lView, tNode);
      if (!node.contains(native)) {
        return null;
      }
      const viewInjector = lView[INJECTOR];
      const registry = viewInjector.get(DEHYDRATED_BLOCK_REGISTRY, null, {
        optional: true
      });
      const renderedLView = getRendererLView(lContainer);
      const rootNodes = [];
      const hydrationState = inferHydrationState(tDetails, lDetails, registry);
      if (renderedLView !== null) {
        collectNativeNodes(renderedLView[TVIEW$1], renderedLView, renderedLView[TVIEW$1].firstChild, rootNodes);
      } else if (hydrationState === 'dehydrated') {
        const transferState = viewInjector.get(TransferState);
        const deferBlockParents = transferState.get(NGH_DEFER_BLOCKS_KEY, {});
        const deferId = lDetails[SSR_UNIQUE_ID];
        const deferData = deferBlockParents[deferId];
        const numberOfRootNodes = deferData[NUM_ROOT_NODES];
        let collectedNodeCount = 0;
        const deferBlockCommentNode = lContainer[NATIVE];
        let currentNode = deferBlockCommentNode.previousSibling;
        while (collectedNodeCount < numberOfRootNodes && currentNode) {
          rootNodes.unshift(currentNode);
          currentNode = currentNode.previousSibling;
          collectedNodeCount++;
        }
      }
      return {
        type: ControlFlowBlockType.Defer,
        state: stringifyState(lDetails[DEFER_BLOCK_STATE]),
        incrementalHydrationState: hydrationState,
        hasErrorBlock: tDetails.errorTmplIndex !== null,
        loadingBlock: {
          exists: tDetails.loadingTmplIndex !== null,
          minimumTime: tDetails.loadingBlockConfig?.[MINIMUM_SLOT] ?? null,
          afterTime: tDetails.loadingBlockConfig?.[LOADING_AFTER_SLOT] ?? null
        },
        placeholderBlock: {
          exists: tDetails.placeholderTmplIndex !== null,
          minimumTime: tDetails.placeholderBlockConfig?.[MINIMUM_SLOT] ?? null
        },
        triggers: tDetails.debug?.triggers ? Array.from(tDetails.debug.triggers).sort() : [],
        hostNode: lContainer[HOST],
        rootNodes
      };
    }
  }
  return null;
};
const forLoopFinder = ({
  lView,
  slotIdx
}) => {
  const slot = lView[slotIdx];
  if (!isRepeaterMetadata(slot)) {
    return null;
  }
  const metadata = slot;
  const liveCollection = metadata.liveCollection;
  const items = [];
  if (liveCollection) {
    for (let j = 0; j < liveCollection.length; j++) {
      items.push(liveCollection.at(j));
    }
  }
  const containerIndex = slotIdx + 1;
  const lContainer = lView[containerIndex];
  const rootNodes = [];
  if (isLContainer(lContainer)) {
    for (let viewIdx = CONTAINER_HEADER_OFFSET; viewIdx < lContainer.length; viewIdx++) {
      const viewAtIdx = lContainer[viewIdx];
      if (isLView(viewAtIdx)) {
        const viewTView = viewAtIdx[TVIEW$1];
        const viewNodes = collectNativeNodes(viewTView, viewAtIdx, viewTView.firstChild, []);
        rootNodes.push(...viewNodes);
      }
    }
  }
  return {
    type: ControlFlowBlockType.For,
    items,
    hasEmptyBlock: metadata.hasEmptyBlock,
    rootNodes,
    hostNode: lContainer[HOST],
    trackExpression: getTrackExpression(metadata)
  };
};
const CONTROL_FLOW_BLOCK_FINDERS = [deferBlockFinder, forLoopFinder];
function findControlFlowBlocks(node, lView, results = []) {
  const tView = lView[TVIEW$1];
  for (let i = HEADER_OFFSET; i < tView.bindingStartIndex; i++) {
    const slot = lView[i];
    for (const finder of CONTROL_FLOW_BLOCK_FINDERS) {
      const block = finder({
        node,
        lView,
        tView,
        slotIdx: i
      });
      if (block) {
        results.push(block);
        break;
      }
    }
    if (isLContainer(slot)) {
      const lContainer = slot;
      if (isLView(lContainer[HOST])) {
        findControlFlowBlocks(node, lContainer[HOST], results);
      }
      for (let j = CONTAINER_HEADER_OFFSET; j < lContainer.length; j++) {
        findControlFlowBlocks(node, lContainer[j], results);
      }
    } else if (isLView(slot)) {
      findControlFlowBlocks(node, slot, results);
    }
  }
  return results;
}
function stringifyState(state) {
  switch (state) {
    case DeferBlockState.Complete:
      return 'complete';
    case DeferBlockState.Loading:
      return 'loading';
    case DeferBlockState.Placeholder:
      return 'placeholder';
    case DeferBlockState.Error:
      return 'error';
    case DeferBlockInternalState.Initial:
      return 'initial';
    default:
      throw new Error(`Unrecognized state ${state}`);
  }
}
function inferHydrationState(tDetails, lDetails, registry) {
  if (registry === null || lDetails[SSR_UNIQUE_ID] === null || tDetails.hydrateTriggers === null || tDetails.hydrateTriggers.has(7)) {
    return 'not-configured';
  }
  return registry.has(lDetails[SSR_UNIQUE_ID]) ? 'dehydrated' : 'hydrated';
}
function getRendererLView(lContainer) {
  if (lContainer.length <= CONTAINER_HEADER_OFFSET) {
    return null;
  }
  const lView = lContainer[CONTAINER_HEADER_OFFSET];
  ngDevMode && assertLView(lView);
  return lView;
}
function isRepeaterMetadata(value) {
  return value !== null && typeof value === 'object' && 'hasEmptyBlock' in value && 'trackByFn' in value && typeof value.trackByFn === 'function';
}
function getTrackExpression(metadata) {
  const trackByFn = metadata.trackByFn;
  if (trackByFn.name === 'ɵɵrepeaterTrackByIndex') {
    return '$index';
  }
  if (trackByFn.name === 'ɵɵrepeaterTrackByIdentity') {
    return 'item';
  }
  return 'function';
}

function getDependenciesFromInjectable(injector, token) {
  const instance = injector.get(token, null, {
    self: true,
    optional: true
  });
  if (instance === null) {
    throw new Error(`Unable to determine instance of ${token} in given injector`);
  }
  const unformattedDependencies = getDependenciesForTokenInInjector(token, injector);
  const resolutionPath = getInjectorResolutionPath(injector);
  const dependencies = unformattedDependencies.map(dep => {
    const formattedDependency = {
      value: dep.value
    };
    const flags = dep.flags;
    formattedDependency.flags = {
      optional: (8 & flags) === 8,
      host: (1 & flags) === 1,
      self: (2 & flags) === 2,
      skipSelf: (4 & flags) === 4
    };
    for (let i = 0; i < resolutionPath.length; i++) {
      const injectorToCheck = resolutionPath[i];
      if (i === 0 && formattedDependency.flags.skipSelf) {
        continue;
      }
      if (formattedDependency.flags.host && injectorToCheck instanceof EnvironmentInjector) {
        break;
      }
      const instance = injectorToCheck.get(dep.token, null, {
        self: true,
        optional: true
      });
      if (instance !== null) {
        if (formattedDependency.flags.host) {
          const firstInjector = resolutionPath[0];
          const lookupFromFirstInjector = firstInjector.get(dep.token, null, {
            ...formattedDependency.flags,
            optional: true
          });
          if (lookupFromFirstInjector !== null) {
            formattedDependency.providedIn = injectorToCheck;
          }
          break;
        }
        formattedDependency.providedIn = injectorToCheck;
        break;
      }
      if (i === 0 && formattedDependency.flags.self) {
        break;
      }
    }
    if (dep.token) formattedDependency.token = dep.token;
    return formattedDependency;
  });
  return {
    instance,
    dependencies
  };
}
function getDependenciesForTokenInInjector(token, injector) {
  const {
    resolverToTokenToDependencies
  } = getFrameworkDIDebugData();
  if (!(injector instanceof NodeInjector)) {
    return resolverToTokenToDependencies.get(injector)?.get?.(token) ?? [];
  }
  const lView = getNodeInjectorLView(injector);
  const tokenDependencyMap = resolverToTokenToDependencies.get(lView);
  const dependencies = tokenDependencyMap?.get(token) ?? [];
  return dependencies.filter(dependency => {
    const dependencyNode = dependency.injectedIn?.tNode;
    if (dependencyNode === undefined) {
      return false;
    }
    const instanceNode = getNodeInjectorTNode(injector);
    assertTNode(dependencyNode);
    assertTNode(instanceNode);
    return dependencyNode === instanceNode;
  });
}
function getProviderImportsContainer(injector) {
  const {
    standaloneInjectorToComponent
  } = getFrameworkDIDebugData();
  if (standaloneInjectorToComponent.has(injector)) {
    return standaloneInjectorToComponent.get(injector);
  }
  const defTypeRef = injector.get(NgModuleRef$1, null, {
    self: true,
    optional: true
  });
  if (defTypeRef === null) {
    return null;
  }
  if (defTypeRef.instance === null) {
    return null;
  }
  return defTypeRef.instance.constructor;
}
function getNodeInjectorProviders(injector) {
  const diResolver = getNodeInjectorTNode(injector);
  const {
    resolverToProviders
  } = getFrameworkDIDebugData();
  const existingProviders = resolverToProviders.get(diResolver) ?? [];
  const specialProviders = Array.from(getAllSpecialProviders()).map(token => ({
    token: token,
    isViewProvider: false,
    provider: token
  }));
  return [...existingProviders, ...specialProviders];
}
function getProviderImportPaths(providerImportsContainer) {
  const providerToPath = new Map();
  const visitedContainers = new Set();
  const visitor = walkProviderTreeToDiscoverImportPaths(providerToPath, visitedContainers);
  walkProviderTree(providerImportsContainer, visitor, [], new Set());
  return providerToPath;
}
function walkProviderTreeToDiscoverImportPaths(providerToPath, visitedContainers) {
  return (provider, container) => {
    if (!providerToPath.has(provider)) {
      providerToPath.set(provider, [container]);
    }
    if (!visitedContainers.has(container)) {
      for (const prov of providerToPath.keys()) {
        const existingImportPath = providerToPath.get(prov);
        let containerDef = getInjectorDef(container);
        if (!containerDef) {
          const ngModule = container.ngModule;
          containerDef = getInjectorDef(ngModule);
        }
        if (!containerDef) {
          return;
        }
        const lastContainerAddedToPath = existingImportPath[0];
        let isNextStepInPath = false;
        deepForEach(containerDef.imports, moduleImport => {
          if (isNextStepInPath) {
            return;
          }
          isNextStepInPath = moduleImport.ngModule === lastContainerAddedToPath || moduleImport === lastContainerAddedToPath;
          if (isNextStepInPath) {
            providerToPath.get(prov)?.unshift(container);
          }
        });
      }
    }
    visitedContainers.add(container);
  };
}
function getEnvironmentInjectorProviders(injector) {
  const providerRecordsWithoutImportPaths = getFrameworkDIDebugData().resolverToProviders.get(injector) ?? [];
  if (isPlatformInjector(injector)) {
    return providerRecordsWithoutImportPaths;
  }
  const providerImportsContainer = getProviderImportsContainer(injector);
  if (providerImportsContainer === null) {
    return providerRecordsWithoutImportPaths;
  }
  const providerToPath = getProviderImportPaths(providerImportsContainer);
  const providerRecords = [];
  for (const providerRecord of providerRecordsWithoutImportPaths) {
    const provider = providerRecord.provider;
    const token = provider.provide;
    if (token === ENVIRONMENT_INITIALIZER || token === INJECTOR_DEF_TYPES) {
      continue;
    }
    let importPath = providerToPath.get(provider) ?? [];
    const def = getComponentDef(providerImportsContainer);
    const isStandaloneComponent = !!def?.standalone;
    if (isStandaloneComponent) {
      importPath = [providerImportsContainer, ...importPath];
    }
    providerRecords.push({
      ...providerRecord,
      importPath
    });
  }
  return providerRecords;
}
function isPlatformInjector(injector) {
  return injector instanceof R3Injector && injector.scopes.has('platform');
}
function getInjectorProviders(injector) {
  if (injector instanceof NodeInjector) {
    return getNodeInjectorProviders(injector);
  } else if (injector instanceof EnvironmentInjector) {
    return getEnvironmentInjectorProviders(injector);
  }
  throwError('getInjectorProviders only supports NodeInjector and EnvironmentInjector');
}
function getInjectorMetadata(injector) {
  if (injector instanceof NodeInjector) {
    const lView = getNodeInjectorLView(injector);
    const tNode = getNodeInjectorTNode(injector);
    assertTNodeForLView(tNode, lView);
    return {
      type: 'element',
      source: getNativeByTNode(tNode, lView)
    };
  }
  if (injector instanceof R3Injector) {
    return {
      type: 'environment',
      source: injector.source ?? null
    };
  }
  if (injector instanceof NullInjector) {
    return {
      type: 'null',
      source: null
    };
  }
  return null;
}
function getInjectorResolutionPath(injector) {
  const resolutionPath = [injector];
  getInjectorResolutionPathHelper(injector, resolutionPath);
  return resolutionPath;
}
function getInjectorResolutionPathHelper(injector, resolutionPath) {
  const parent = getInjectorParent(injector);
  if (parent === null) {
    if (injector instanceof NodeInjector) {
      const firstInjector = resolutionPath[0];
      if (firstInjector instanceof NodeInjector) {
        const moduleInjector = getModuleInjectorOfNodeInjector(firstInjector);
        if (moduleInjector === null) {
          throwError('NodeInjector must have some connection to the module injector tree');
        }
        resolutionPath.push(moduleInjector);
        getInjectorResolutionPathHelper(moduleInjector, resolutionPath);
      }
      return resolutionPath;
    }
  } else {
    resolutionPath.push(parent);
    getInjectorResolutionPathHelper(parent, resolutionPath);
  }
  return resolutionPath;
}
function getInjectorParent(injector) {
  if (injector instanceof R3Injector) {
    return injector.parent;
  }
  let tNode;
  let lView;
  if (injector instanceof NodeInjector) {
    tNode = getNodeInjectorTNode(injector);
    lView = getNodeInjectorLView(injector);
  } else if (injector instanceof NullInjector) {
    return null;
  } else if (injector instanceof ChainedInjector) {
    return injector.parentInjector;
  } else {
    throwError('getInjectorParent only support injectors of type R3Injector, NodeInjector, NullInjector');
  }
  const parentLocation = getParentInjectorLocation(tNode, lView);
  if (hasParentInjector(parentLocation)) {
    const parentInjectorIndex = getParentInjectorIndex(parentLocation);
    const parentLView = getParentInjectorView(parentLocation, lView);
    const parentTView = parentLView[TVIEW$1];
    const parentTNode = parentTView.data[parentInjectorIndex + 8];
    return new NodeInjector(parentTNode, parentLView);
  } else {
    const chainedInjector = lView[INJECTOR];
    const injectorParent = chainedInjector.injector?.parent;
    if (injectorParent instanceof NodeInjector) {
      return injectorParent;
    }
  }
  return null;
}
function getModuleInjectorOfNodeInjector(injector) {
  let lView;
  if (injector instanceof NodeInjector) {
    lView = getNodeInjectorLView(injector);
  } else {
    throwError('getModuleInjectorOfNodeInjector must be called with a NodeInjector');
  }
  const inj = lView[INJECTOR];
  const moduleInjector = inj instanceof ChainedInjector ? inj.parentInjector : inj.parent;
  if (!moduleInjector) {
    throwError('NodeInjector must have some connection to the module injector tree');
  }
  return moduleInjector;
}

function isComputedNode(node) {
  return node.kind === 'computed';
}
function isTemplateEffectNode(node) {
  return node.kind === 'template';
}
function isEffectNode(node) {
  return node.kind === 'effect';
}
function isSignalNode(node) {
  return node.kind === 'signal';
}
function isLinkedSignalNode(node) {
  return node.kind === 'linkedSignal';
}
function isAfterRenderEffectPhaseNode(node) {
  return node.kind === 'afterRenderEffectPhase';
}
function getTemplateConsumer(injector) {
  const tNode = getNodeInjectorTNode(injector);
  assertTNode(tNode);
  const lView = getNodeInjectorLView(injector);
  assertLView(lView);
  const templateLView = lView[tNode.index];
  if (isLView(templateLView)) {
    return templateLView[REACTIVE_TEMPLATE_CONSUMER] ?? null;
  }
  return null;
}
const signalDebugMap = new WeakMap();
const signalDebugNodeMap = new Map();
const watchCleanupRegistry = new FinalizationRegistry(({
  id
}) => {
  unwatchSignal(id);
  signalDebugNodeMap.delete(id);
});
let counter$1 = 0;
function isWatched(id) {
  const watchRef = signalDebugNodeMap.get(id)?.watch;
  if (!watchRef) return false;
  const watchNode = watchRef.deref();
  return watchNode !== undefined && !watchNode.destroyed;
}
function getNodesAndEdgesFromSignalMap(signalMap) {
  const nodes = Array.from(signalMap.keys());
  const debugSignalGraphNodes = [];
  const edges = [];
  for (const [consumer, producers] of signalMap.entries()) {
    const consumerIndex = nodes.indexOf(consumer);
    let id = signalDebugMap.get(consumer);
    if (!id) {
      counter$1++;
      id = counter$1.toString();
      signalDebugMap.set(consumer, id);
    }
    if (isComputedNode(consumer)) {
      if (!signalDebugNodeMap.has(id)) {
        signalDebugNodeMap.set(id, {
          node: new WeakRef(consumer)
        });
        watchCleanupRegistry.register(consumer, {
          id
        });
      }
      debugSignalGraphNodes.push({
        label: consumer.debugName,
        value: consumer.value,
        kind: consumer.kind,
        epoch: consumer.version,
        debuggableFn: consumer.computation,
        watched: isWatched(id),
        id
      });
    } else if (isSignalNode(consumer)) {
      if (!signalDebugNodeMap.has(id)) {
        signalDebugNodeMap.set(id, {
          node: new WeakRef(consumer)
        });
        watchCleanupRegistry.register(consumer, {
          id
        });
      }
      debugSignalGraphNodes.push({
        label: consumer.debugName,
        value: consumer.value,
        kind: consumer.kind,
        epoch: consumer.version,
        watched: isWatched(id),
        id
      });
    } else if (isTemplateEffectNode(consumer)) {
      debugSignalGraphNodes.push({
        label: consumer.debugName ?? consumer.lView?.[HOST]?.tagName?.toLowerCase?.(),
        kind: consumer.kind,
        epoch: consumer.version,
        debuggableFn: consumer.lView?.[CONTEXT]?.constructor,
        watched: false,
        id
      });
    } else if (isLinkedSignalNode(consumer)) {
      if (!signalDebugNodeMap.has(id)) {
        signalDebugNodeMap.set(id, {
          node: new WeakRef(consumer)
        });
        watchCleanupRegistry.register(consumer, {
          id
        });
      }
      debugSignalGraphNodes.push({
        label: consumer.debugName,
        value: consumer.value,
        kind: consumer.kind,
        epoch: consumer.version,
        debuggableFn: consumer.computation,
        watched: isWatched(id),
        id
      });
    } else if (isEffectNode(consumer)) {
      debugSignalGraphNodes.push({
        label: consumer.debugName,
        kind: consumer.kind,
        epoch: consumer.version,
        debuggableFn: consumer.userFn,
        id
      });
    } else if (isAfterRenderEffectPhaseNode(consumer)) {
      debugSignalGraphNodes.push({
        label: consumer.debugName,
        kind: consumer.kind,
        epoch: consumer.version,
        debuggableFn: consumer.userFn,
        id
      });
    } else {
      debugSignalGraphNodes.push({
        label: consumer.debugName,
        kind: consumer.kind,
        epoch: consumer.version,
        watched: false,
        id
      });
    }
    for (const producer of producers) {
      edges.push({
        consumer: consumerIndex,
        producer: nodes.indexOf(producer)
      });
    }
  }
  return {
    nodes: debugSignalGraphNodes,
    edges
  };
}
function extractEffectsFromInjector(injector) {
  let diResolver = injector;
  if (injector instanceof NodeInjector) {
    const lView = getNodeInjectorLView(injector);
    diResolver = lView;
  }
  const resolverToEffects = getFrameworkDIDebugData().resolverToEffects;
  const effects = resolverToEffects.get(diResolver) ?? [];
  return effects.map(effect => {
    if (effect instanceof EffectRefImpl) {
      return effect[SIGNAL];
    } else {
      return effect.signal[SIGNAL];
    }
  });
}
function extractSignalNodesAndEdgesFromRoots(nodes, signalDependenciesMap = new Map()) {
  for (const node of nodes) {
    if (signalDependenciesMap.has(node)) {
      continue;
    }
    const producerNodes = [];
    for (let link = node.producers; link !== undefined; link = link.nextProducer) {
      const producer = link.producer;
      producerNodes.push(producer);
    }
    signalDependenciesMap.set(node, producerNodes);
    extractSignalNodesAndEdgesFromRoots(producerNodes, signalDependenciesMap);
  }
  return signalDependenciesMap;
}
function getSignalGraph(injector) {
  let templateConsumer = null;
  if (!(injector instanceof NodeInjector) && !(injector instanceof R3Injector)) {
    return throwError('getSignalGraph must be called with a NodeInjector or R3Injector');
  }
  if (injector instanceof NodeInjector) {
    templateConsumer = getTemplateConsumer(injector);
  }
  const nonTemplateEffectNodes = extractEffectsFromInjector(injector);
  const signalNodes = templateConsumer ? [templateConsumer, ...nonTemplateEffectNodes] : nonTemplateEffectNodes;
  const signalDependenciesMap = extractSignalNodesAndEdgesFromRoots(signalNodes);
  return getNodesAndEdgesFromSignalMap(signalDependenciesMap);
}
function toggleWatchSignal(id) {
  const entry = signalDebugNodeMap.get(id);
  if (!entry) {
    console.warn(`Could not find signal with ID "${id}". The ID may be wrong, or it could have been garbage collected.`);
    return;
  }
  if (entry.watch) {
    const activeWatch = entry.watch.deref();
    if (activeWatch && !activeWatch.destroyed) {
      unwatchSignal(id);
      return;
    }
  }
  const node = entry.node.deref();
  if (!node) {
    unwatchSignal(id);
    signalDebugNodeMap.delete(id);
    return;
  }
  const watchNode = createDebugWatchNode(node);
  entry.watch = new WeakRef(watchNode);
  runDebugWatch(watchNode);
}
function createDebugWatchNode(targetNode) {
  const node = {
    ...REACTIVE_NODE,
    consumerIsAlwaysLive: true,
    consumerAllowSignalWrites: true,
    dirty: true,
    kind: 'effect',
    targetNode: new WeakRef(targetNode),
    destroyed: false,
    consumerMarkedDirty: () => {
      if (node.destroyed) return;
      queueMicrotask(() => runDebugWatch(node));
    }
  };
  return node;
}
function runDebugWatch(node) {
  if (node.destroyed) return;
  const targetNode = node.targetNode.deref();
  if (!targetNode) {
    node.destroyed = true;
    consumerDestroy(node);
    return;
  }
  node.dirty = false;
  if (node.version > 0 && !consumerPollProducersForChange(node)) {
    return;
  }
  node.version++;
  const prevConsumer = consumerBeforeComputation(node);
  try {
    producerUpdateValueVersion(targetNode);
    producerAccessed(targetNode);
    const name = targetNode.debugName ? targetNode.debugName : 'DevTools signal watch';
    if ((isComputedNode(targetNode) || isLinkedSignalNode(targetNode)) && targetNode.value === ERRORED) {
      console.error(`[${name} (error)]:`, targetNode.error);
      return;
    }
    const value = isSignalNode(targetNode) || isComputedNode(targetNode) || isLinkedSignalNode(targetNode) ? targetNode.value : undefined;
    console.log(`[${name}]:`, value);
  } finally {
    consumerAfterComputation(node, prevConsumer);
  }
}
function unwatchSignal(id) {
  const entry = signalDebugNodeMap.get(id);
  if (entry?.watch) {
    const watchNode = entry.watch.deref();
    if (watchNode && !watchNode.destroyed) {
      watchNode.destroyed = true;
      consumerDestroy(watchNode);
    }
    entry.watch = undefined;
  }
}

let changeDetectionRuns = 0;
let changeDetectionSyncRuns = 0;
let counter = 0;
let nextInstanceDeepLinkId = 0;
const instanceDeepLinkIds = new WeakMap();
function getComponentInstanceDeepLinkId(instance) {
  return instanceDeepLinkIds.get(instance);
}
function assignComponentInstanceDeepLinkId(instance) {
  const id = nextInstanceDeepLinkId++;
  instanceDeepLinkIds.set(instance, id);
  return id;
}
const DEEP_LINK_SCHEME = 'angular-devtools';
function getDeepLinkProperties(instance) {
  if (typeof __NG_DEVTOOLS_CONNECTED__ === 'undefined' || !__NG_DEVTOOLS_CONNECTED__) return undefined;
  const instanceId = getComponentInstanceDeepLinkId(instance) ?? assignComponentInstanceDeepLinkId(instance);
  return {
    url: `${DEEP_LINK_SCHEME}://component/${instanceId}`,
    description: 'Component'
  };
}
const eventsStack = [];
function getBaseDocUrl() {
  const full = VERSION.full;
  const isPreRelease = full.includes('-next') || full.includes('-rc') || full === '22.2.3';
  const prefix = isPreRelease ? 'next' : `v${VERSION.major}`;
  return `https://${prefix}.angular.dev`;
}
function getLifecycleHookDocUrl(hookName) {
  const match = hookName.match(/:(ng\w+)$/);
  if (!match) return undefined;
  const lifecycleHook = match[1].toLowerCase();
  const baseUrl = getBaseDocUrl();
  return `${baseUrl}/guide/components/lifecycle#${lifecycleHook}`;
}
function getProfilerEventDocUrl(event, entryName) {
  const baseUrl = getBaseDocUrl();
  switch (event) {
    case ProfilerEvent.ChangeDetectionStart:
    case ProfilerEvent.ChangeDetectionEnd:
    case ProfilerEvent.ChangeDetectionSyncStart:
    case ProfilerEvent.ChangeDetectionSyncEnd:
      return `${baseUrl}/best-practices/runtime-performance`;
    case ProfilerEvent.AfterRenderHooksStart:
    case ProfilerEvent.AfterRenderHooksEnd:
      return `${baseUrl}/guide/components/lifecycle#aftereveryrender-and-afternextrender`;
    case ProfilerEvent.DeferBlockStateStart:
    case ProfilerEvent.DeferBlockStateEnd:
      return `${baseUrl}/guide/defer`;
    case ProfilerEvent.LifecycleHookStart:
      return getLifecycleHookDocUrl(entryName);
    default:
      return undefined;
  }
}
function resolveTimestampDetail(detail, docUrl) {
  if (!docUrl) return detail;
  if (!detail) return {
    description: 'Documentation',
    url: docUrl
  };
  return detail;
}
function measureStart(startEvent) {
  eventsStack.push([startEvent, counter]);
  console.timeStamp('Event_' + startEvent + '_' + counter++);
}
function measureEnd(startEvent, entryName, color, detail) {
  let top;
  do {
    top = eventsStack.pop();
    assertDefined(top, 'Profiling error: could not find start event entry ' + startEvent);
  } while (top[0] !== startEvent);
  const docUrl = getProfilerEventDocUrl(startEvent, entryName);
  const resolvedDetail = resolveTimestampDetail(detail, docUrl);
  console.timeStamp(entryName, 'Event_' + top[0] + '_' + top[1], undefined, '\u{1F170}\uFE0F Angular', undefined, color, resolvedDetail);
}
const chromeDevToolsInjectorProfiler = event => {
  const eventType = event.type;
  if (eventType === 5) {
    measureStart(100);
  } else if (eventType === 1) {
    const token = event.context.token;
    measureEnd(100, getProviderTokenMeasureName(token), 'tertiary-dark');
  }
};
const devToolsProfiler = (event, instance, eventFn) => {
  switch (event) {
    case ProfilerEvent.BootstrapApplicationStart:
    case ProfilerEvent.BootstrapComponentStart:
    case ProfilerEvent.ChangeDetectionStart:
    case ProfilerEvent.ChangeDetectionSyncStart:
    case ProfilerEvent.AfterRenderHooksStart:
    case ProfilerEvent.ComponentStart:
    case ProfilerEvent.DeferBlockStateStart:
    case ProfilerEvent.DynamicComponentStart:
    case ProfilerEvent.TemplateCreateStart:
    case ProfilerEvent.LifecycleHookStart:
    case ProfilerEvent.TemplateUpdateStart:
    case ProfilerEvent.HostBindingsUpdateStart:
    case ProfilerEvent.OutputStart:
      {
        measureStart(event);
        break;
      }
    case ProfilerEvent.BootstrapApplicationEnd:
      {
        measureEnd(ProfilerEvent.BootstrapApplicationStart, 'Bootstrap application', 'primary-dark');
        break;
      }
    case ProfilerEvent.BootstrapComponentEnd:
      {
        measureEnd(ProfilerEvent.BootstrapComponentStart, 'Bootstrap component', 'primary-dark');
        break;
      }
    case ProfilerEvent.ChangeDetectionEnd:
      {
        changeDetectionSyncRuns = 0;
        measureEnd(ProfilerEvent.ChangeDetectionStart, 'Change detection ' + changeDetectionRuns++, 'primary-dark');
        break;
      }
    case ProfilerEvent.ChangeDetectionSyncEnd:
      {
        measureEnd(ProfilerEvent.ChangeDetectionSyncStart, 'Synchronization ' + changeDetectionSyncRuns++, 'primary');
        break;
      }
    case ProfilerEvent.AfterRenderHooksEnd:
      {
        measureEnd(ProfilerEvent.AfterRenderHooksStart, 'After render hooks', 'primary');
        break;
      }
    case ProfilerEvent.ComponentEnd:
      {
        const typeName = getComponentMeasureName(instance);
        measureEnd(ProfilerEvent.ComponentStart, typeName, 'primary-light', getDeepLinkProperties(instance));
        break;
      }
    case ProfilerEvent.DeferBlockStateEnd:
      {
        measureEnd(ProfilerEvent.DeferBlockStateStart, 'Defer block', 'primary-dark');
        break;
      }
    case ProfilerEvent.DynamicComponentEnd:
      {
        measureEnd(ProfilerEvent.DynamicComponentStart, 'Dynamic component creation', 'primary-dark');
        break;
      }
    case ProfilerEvent.TemplateUpdateEnd:
      {
        measureEnd(ProfilerEvent.TemplateUpdateStart, stringifyForError(eventFn) + ' (update)', 'secondary-dark');
        break;
      }
    case ProfilerEvent.TemplateCreateEnd:
      {
        measureEnd(ProfilerEvent.TemplateCreateStart, stringifyForError(eventFn) + ' (create)', 'secondary');
        break;
      }
    case ProfilerEvent.HostBindingsUpdateEnd:
      {
        measureEnd(ProfilerEvent.HostBindingsUpdateStart, 'HostBindings', 'secondary-dark');
        break;
      }
    case ProfilerEvent.LifecycleHookEnd:
      {
        const typeName = getComponentMeasureName(instance);
        measureEnd(ProfilerEvent.LifecycleHookStart, `${typeName}:${stringifyForError(eventFn)}`, 'tertiary');
        break;
      }
    case ProfilerEvent.OutputEnd:
      {
        measureEnd(ProfilerEvent.OutputStart, stringifyForError(eventFn), 'tertiary-light');
        break;
      }
    default:
      {
        throw new Error('Unexpected profiling event type: ' + event);
      }
  }
};
function getComponentMeasureName(instance) {
  return instance.constructor.name;
}
function getProviderTokenMeasureName(token) {
  if (isTypeProvider(token)) {
    return token.name;
  } else if (token.provide != null) {
    return getProviderTokenMeasureName(token.provide);
  }
  return token.toString();
}
function enableProfiling() {
  performanceMarkFeature('Chrome DevTools profiling');
  if (typeof ngDevMode !== 'undefined' && ngDevMode) {
    const removeInjectorProfiler = setInjectorProfiler(chromeDevToolsInjectorProfiler);
    const removeProfiler = setProfiler(devToolsProfiler);
    return () => {
      removeInjectorProfiler();
      removeProfiler();
    };
  }
  return () => {};
}

function getTransferState(injector) {
  const doc = injector.get(DOCUMENT$1);
  const appId = injector.get(APP_ID);
  const transferState = retrieveTransferredState(doc, appId);
  const filteredEntries = {};
  for (const [key, value] of Object.entries(transferState)) {
    if (!isInternalHydrationTransferStateKey(key)) {
      filteredEntries[key] = value;
    }
  }
  return filteredEntries;
}

const GLOBAL_PUBLISH_EXPANDO_KEY = 'ng';
const internalCoreGlobalUtils = {
  toggleWatchSignal
};
const externalCoreGlobalUtils = {
  'ɵgetDependenciesFromInjectable': getDependenciesFromInjectable,
  'ɵgetInjectorProviders': getInjectorProviders,
  'ɵgetInjectorResolutionPath': getInjectorResolutionPath,
  'ɵgetInjectorMetadata': getInjectorMetadata,
  'ɵsetProfiler': setProfiler,
  'ɵgetSignalGraph': getSignalGraph,
  'ɵgetControlFlowBlocks': getControlFlowBlocks,
  'ɵgetTransferState': getTransferState,
  'ɵgetComponentInstanceDeepLinkId': getComponentInstanceDeepLinkId,
  getDirectiveMetadata: getDirectiveMetadata$1,
  getComponent,
  getContext,
  getListeners,
  getOwningComponent,
  getHostElement,
  getInjector,
  getRootComponents,
  getDirectives,
  applyChanges,
  isSignal,
  enableProfiling
};
let _published = false;
function publishDefaultGlobalUtils$1() {
  if (!_published) {
    _published = true;
    if (typeof window !== 'undefined') {
      setupFrameworkInjectorProfiler();
    }
    for (const [methodName, method] of Object.entries(externalCoreGlobalUtils)) {
      publishGlobalUtil(methodName, method);
    }
    for (const [methodName, method] of Object.entries(internalCoreGlobalUtils)) {
      publishGlobalUtil(methodName, method);
    }
  }
}
function publishGlobalUtil(name, fn) {
  publishUtil(name, fn);
}
function publishNonCoreGlobalUtil(name, fn) {
  publishUtil(name, fn);
}
function publishUtil(name, fn) {
  if (typeof COMPILED === 'undefined' || !COMPILED) {
    const w = _global;
    ngDevMode && assertDefined(fn, 'function not defined');
    w[GLOBAL_PUBLISH_EXPANDO_KEY] ??= {};
    w[GLOBAL_PUBLISH_EXPANDO_KEY][name] = fn;
  }
}

const TESTABILITY = new InjectionToken('');
const TESTABILITY_GETTER = new InjectionToken('');
const USE_PENDING_TASKS = new InjectionToken('USE_PENDING_TASKS', {
  providedIn: 'root',
  factory: () => typeof Zone === 'undefined'
});
class Testability {
  _ngZone;
  registry;
  _isZoneStable = true;
  _callbacks = [];
  _taskTrackingZone = null;
  _destroyRef;
  pendingTasksInternal = inject(PendingTasksInternal);
  _usePendingTasks = inject(USE_PENDING_TASKS);
  constructor(_ngZone, registry, testabilityGetter) {
    this._ngZone = _ngZone;
    this.registry = registry;
    if (isInInjectionContext()) {
      this._destroyRef = inject(DestroyRef, {
        optional: true
      }) ?? undefined;
    }
    if (!_testabilityGetter) {
      setTestabilityGetter(testabilityGetter);
      testabilityGetter.addToWindow(registry);
    }
    this._watchAngularEvents();
    _ngZone.run(() => {
      this._taskTrackingZone = typeof Zone == 'undefined' ? null : Zone.current.get('TaskTrackingZone');
    });
  }
  _watchAngularEvents() {
    const onUnstableSubscription = this._ngZone.onUnstable.subscribe({
      next: () => {
        this._isZoneStable = false;
      }
    });
    let pendingTasksSubscription;
    let onStableSubscription;
    this._ngZone.runOutsideAngular(() => {
      if (this._usePendingTasks) {
        pendingTasksSubscription = this.pendingTasksInternal.hasPendingTasksObservable.subscribe(() => {
          if (this.isStable()) {
            this._ngZone.runOutsideAngular(() => {
              this._runCallbacksIfReady();
            });
          }
        });
      }
      onStableSubscription = this._ngZone.onStable.subscribe({
        next: () => {
          NgZone.assertNotInAngularZone();
          queueMicrotask(() => {
            this._isZoneStable = true;
            this._runCallbacksIfReady();
          });
        }
      });
    });
    this._destroyRef?.onDestroy(() => {
      onUnstableSubscription.unsubscribe();
      pendingTasksSubscription?.unsubscribe();
      onStableSubscription.unsubscribe();
    });
  }
  isStable() {
    return this._isZoneStable && !this._ngZone.hasPendingMacrotasks && (!this._usePendingTasks || !this.pendingTasksInternal.hasPendingTasks);
  }
  _runCallbacksIfReady() {
    if (this.isStable()) {
      queueMicrotask(() => {
        while (this._callbacks.length !== 0) {
          let cb = this._callbacks.pop();
          clearTimeout(cb.timeoutId);
          cb.doneCb();
        }
      });
    } else {
      let pending = this.getPendingTasks();
      this._callbacks = this._callbacks.filter(cb => {
        if (cb.updateCb && cb.updateCb(pending)) {
          clearTimeout(cb.timeoutId);
          return false;
        }
        return true;
      });
    }
  }
  getPendingTasks() {
    if (!this._taskTrackingZone) {
      return [];
    }
    return this._taskTrackingZone.macroTasks.map(t => {
      return {
        source: t.source,
        creationLocation: t.creationLocation,
        data: t.data
      };
    });
  }
  addCallback(cb, timeout, updateCb) {
    let timeoutId = -1;
    if (timeout && timeout > 0) {
      timeoutId = setTimeout(() => {
        this._callbacks = this._callbacks.filter(cb => cb.timeoutId !== timeoutId);
        cb();
      }, timeout);
    }
    this._callbacks.push({
      doneCb: cb,
      timeoutId: timeoutId,
      updateCb: updateCb
    });
  }
  whenStable(doneCb, timeout, updateCb) {
    if (updateCb && !this._taskTrackingZone) {
      throw new Error('Task tracking zone is required when passing an update callback to ' + 'whenStable(). Is "zone.js/plugins/task-tracking" loaded?');
    }
    this.addCallback(doneCb, timeout, updateCb);
    this._runCallbacksIfReady();
  }
  registerApplication(token) {
    this.registry.registerApplication(token, this);
  }
  unregisterApplication(token) {
    this.registry.unregisterApplication(token);
  }
  findProviders(using, provider, exactMatch) {
    return [];
  }
  static ɵfac = function Testability_Factory(__ngFactoryType__) {
    return new (__ngFactoryType__ || Testability)(__inject(NgZone), __inject(TestabilityRegistry), __inject(TESTABILITY_GETTER));
  };
  static ɵprov = /*@__PURE__*/__defineInjectable({
    token: Testability,
    factory: Testability.ɵfac
  });
}
(() => {
  (typeof ngDevMode === "undefined" || ngDevMode) && setClassMetadata(Testability, [{
    type: Injectable
  }], () => [{
    type: NgZone
  }, {
    type: TestabilityRegistry
  }, {
    type: undefined,
    decorators: [{
      type: Inject,
      args: [TESTABILITY_GETTER]
    }]
  }], null);
})();
class TestabilityRegistry {
  _applications = new Map();
  registerApplication(token, testability) {
    this._applications.set(token, testability);
  }
  unregisterApplication(token) {
    this._applications.delete(token);
  }
  unregisterAllApplications() {
    this._applications.clear();
  }
  getTestability(elem) {
    return this._applications.get(elem) || null;
  }
  getAllTestabilities() {
    return Array.from(this._applications.values());
  }
  getAllRootElements() {
    return Array.from(this._applications.keys());
  }
  findTestabilityInTree(elem, findInAncestors = true) {
    return _testabilityGetter?.findTestabilityInTree(this, elem, findInAncestors) ?? null;
  }
  static ɵfac = function TestabilityRegistry_Factory(__ngFactoryType__) {
    return new (__ngFactoryType__ || TestabilityRegistry)();
  };
  static ɵprov = /*@__PURE__*/__defineInjectable({
    token: TestabilityRegistry,
    factory: TestabilityRegistry.ɵfac,
    providedIn: 'platform'
  });
}
(() => {
  (typeof ngDevMode === "undefined" || ngDevMode) && setClassMetadata(TestabilityRegistry, [{
    type: Injectable,
    args: [{
      providedIn: 'platform'
    }]
  }], null, null);
})();
function setTestabilityGetter(getter) {
  _testabilityGetter = getter;
}
let _testabilityGetter;

const APP_BOOTSTRAP_LISTENER = new InjectionToken(ngDevMode ? 'appBootstrapListener' : '');
function publishDefaultGlobalUtils() {
  ngDevMode && publishDefaultGlobalUtils$1();
}
function publishSignalConfiguration() {
  setThrowInvalidWriteToSignalError(node => {
    let errorMessage = '';
    if (ngDevMode) {
      const activeConsumer = getActiveConsumer();
      if (activeConsumer && isReactiveLViewConsumer(activeConsumer)) {
        errorMessage = 'Writing to signals is not allowed while Angular renders the template (eg. interpolations)';
        const componentName = activeConsumer.lView && getDeclarationComponentDef(activeConsumer.lView)?.type?.name;
        if (componentName) {
          errorMessage += `. Template location: '${componentName}' component`;
        }
      } else {
        errorMessage = 'Writing to signals is not allowed in a `computed`';
      }
      if (node.debugName) {
        errorMessage += `. Signal: '${node.debugName}'`;
      }
    }
    throw new RuntimeError(-600, errorMessage);
  });
}
const MAXIMUM_REFRESH_RERUNS = 10;
function optionsReducer(dst, objs) {
  if (Array.isArray(objs)) {
    return objs.reduce(optionsReducer, dst);
  }
  return {
    ...dst,
    ...objs
  };
}
class ApplicationRef {
  _runningTick = false;
  _destroyed = false;
  _destroyListeners = [];
  _views = [];
  internalErrorHandler = inject(INTERNAL_APPLICATION_ERROR_HANDLER);
  afterRenderManager = inject(AfterRenderManager);
  zonelessEnabled = inject(ZONELESS_ENABLED);
  rootEffectScheduler = inject(EffectScheduler);
  dirtyFlags = 0;
  tracingSnapshot = null;
  allTestViews = new Set();
  autoDetectTestViews = new Set();
  includeAllTestViews = false;
  afterTick = new Subject();
  get allViews() {
    return [...(this.includeAllTestViews ? this.allTestViews : this.autoDetectTestViews).keys(), ...this._views];
  }
  get destroyed() {
    return this._destroyed;
  }
  componentTypes = [];
  components = [];
  internalPendingTask = inject(PendingTasksInternal);
  get isStable() {
    return this.internalPendingTask.hasPendingTasksObservable.pipe(map(pending => !pending));
  }
  constructor() {
    inject(TracingService, {
      optional: true
    });
  }
  whenStable() {
    let subscription;
    return new Promise(resolve => {
      subscription = this.isStable.subscribe({
        next: stable => {
          if (stable) {
            resolve();
          }
        }
      });
    }).finally(() => {
      subscription.unsubscribe();
    });
  }
  _injector = inject(EnvironmentInjector);
  _rendererFactory = null;
  get injector() {
    return this._injector;
  }
  bootstrap(component, rootSelectorOrNode) {
    return this.bootstrapImpl(component, rootSelectorOrNode);
  }
  bootstrapImpl(component, hostElementOrOptions, injector = Injector.NULL) {
    const ngZone = this._injector.get(NgZone);
    return ngZone.run(() => {
      profiler(ProfilerEvent.BootstrapComponentStart);
      (typeof ngDevMode === 'undefined' || ngDevMode) && warnIfDestroyed(this._destroyed);
      const initStatus = this._injector.get(ApplicationInitStatus);
      if (!initStatus.done) {
        let errorMessage = '';
        if (typeof ngDevMode === 'undefined' || ngDevMode) {
          const standalone = isStandalone(component);
          errorMessage = 'Cannot bootstrap as there are still asynchronous initializers running.' + (standalone ? '' : ' Bootstrap components in the `ngDoBootstrap` method of the root module.');
        }
        throw new RuntimeError(405, errorMessage);
      }
      const componentDef = getComponentDef(component);
      const ngModule = this._injector.get(NgModuleRef$1);
      const componentFactory = new ComponentFactory(componentDef, ngModule);
      this.componentTypes.push(component);
      const {
        hostElement,
        directives,
        bindings
      } = normalizeBootstrapOptions(hostElementOrOptions);
      const selectorOrNode = hostElement || componentFactory.selector;
      const compRef = componentFactory.create(injector, [], selectorOrNode, ngModule.injector, directives, bindings);
      const nativeElement = compRef.location.nativeElement;
      const testability = compRef.injector.get(TESTABILITY, null);
      testability?.registerApplication(nativeElement);
      compRef.onDestroy(() => {
        this.detachView(compRef.hostView);
        remove(this.components, compRef);
        testability?.unregisterApplication(nativeElement);
      });
      this._loadComponent(compRef);
      if (typeof ngDevMode === 'undefined' || ngDevMode) {
        const _console = this._injector.get(Console);
        _console.log(`Angular is running in development mode.`);
      }
      profiler(ProfilerEvent.BootstrapComponentEnd, compRef);
      return compRef;
    });
  }
  tick() {
    if (!this.zonelessEnabled) {
      this.dirtyFlags |= 1;
    }
    this._tick();
  }
  _tick() {
    profiler(ProfilerEvent.ChangeDetectionStart);
    if (this.tracingSnapshot !== null) {
      this.tracingSnapshot.run(TracingAction.CHANGE_DETECTION, this.tickImpl);
    } else {
      this.tickImpl();
    }
  }
  tickImpl = () => {
    (typeof ngDevMode === 'undefined' || ngDevMode) && warnIfDestroyed(this._destroyed);
    if (this._runningTick) {
      profiler(ProfilerEvent.ChangeDetectionEnd);
      throw new RuntimeError(101, ngDevMode && 'ApplicationRef.tick is called recursively');
    }
    const prevConsumer = setActiveConsumer(null);
    try {
      this._runningTick = true;
      this.synchronize();
      if (typeof ngDevMode === 'undefined' || ngDevMode) {
        for (let view of this.allViews) {
          view.checkNoChanges();
        }
      }
    } finally {
      this._runningTick = false;
      this.tracingSnapshot?.dispose();
      this.tracingSnapshot = null;
      setActiveConsumer(prevConsumer);
      this.afterTick.next();
      profiler(ProfilerEvent.ChangeDetectionEnd);
    }
  };
  synchronize() {
    if (this._rendererFactory === null && !this._injector.destroyed) {
      this._rendererFactory = this._injector.get(RendererFactory2, null, {
        optional: true
      });
    }
    let runs = 0;
    while (this.dirtyFlags !== 0 && runs++ < MAXIMUM_REFRESH_RERUNS) {
      profiler(ProfilerEvent.ChangeDetectionSyncStart);
      try {
        this.synchronizeOnce();
      } finally {
        profiler(ProfilerEvent.ChangeDetectionSyncEnd);
      }
    }
    if ((typeof ngDevMode === 'undefined' || ngDevMode) && runs >= MAXIMUM_REFRESH_RERUNS) {
      throw new RuntimeError(103, ngDevMode && 'Infinite change detection while refreshing application views. ' + 'Ensure views are not calling `markForCheck` on every template execution or ' + 'that afterRender hooks always mark views for check.');
    }
  }
  synchronizeOnce() {
    if (this.dirtyFlags & 16) {
      this.dirtyFlags &= -17;
      this.rootEffectScheduler.flush();
    }
    let ranDetectChanges = false;
    if (this.dirtyFlags & 7) {
      const useGlobalCheck = Boolean(this.dirtyFlags & 1);
      this.dirtyFlags &= -8;
      this.dirtyFlags |= 8;
      for (let {
        _lView
      } of this.allViews) {
        if (!useGlobalCheck && !requiresRefreshOrTraversal(_lView)) {
          continue;
        }
        const mode = useGlobalCheck && !this.zonelessEnabled ? 0 : 1;
        detectChangesInternal(_lView, mode);
        ranDetectChanges = true;
      }
      this.dirtyFlags &= -5;
      this.syncDirtyFlagsWithViews();
      if (this.dirtyFlags & (7 | 16)) {
        return;
      }
    }
    if (!ranDetectChanges) {
      this._rendererFactory?.begin?.();
      this._rendererFactory?.end?.();
    }
    if (this.dirtyFlags & 8) {
      this.dirtyFlags &= -9;
      this.afterRenderManager.execute();
    }
    this.syncDirtyFlagsWithViews();
  }
  syncDirtyFlagsWithViews() {
    if (this.allViews.some(({
      _lView
    }) => requiresRefreshOrTraversal(_lView))) {
      this.dirtyFlags |= 2;
      return;
    } else {
      this.dirtyFlags &= -8;
    }
  }
  attachView(viewRef) {
    (typeof ngDevMode === 'undefined' || ngDevMode) && warnIfDestroyed(this._destroyed);
    const view = viewRef;
    this._views.push(view);
    view.attachToAppRef(this);
  }
  detachView(viewRef) {
    (typeof ngDevMode === 'undefined' || ngDevMode) && warnIfDestroyed(this._destroyed);
    const view = viewRef;
    remove(this._views, view);
    view.detachFromAppRef();
  }
  _loadComponent(componentRef) {
    this.attachView(componentRef.hostView);
    try {
      this.tick();
    } catch (e) {
      this.internalErrorHandler(e);
    }
    this.components.push(componentRef);
    const listeners = this._injector.get(APP_BOOTSTRAP_LISTENER, []);
    if (ngDevMode && !Array.isArray(listeners)) {
      throw new RuntimeError(-209, 'Unexpected type of the `APP_BOOTSTRAP_LISTENER` token value ' + `(expected an array, but got ${typeof listeners}). ` + 'Please check that the `APP_BOOTSTRAP_LISTENER` token is configured as a ' + '`multi: true` provider.');
    }
    listeners.forEach(listener => listener(componentRef));
  }
  ngOnDestroy() {
    if (this._destroyed) return;
    try {
      this._destroyListeners.forEach(listener => listener());
      this._views.slice().forEach(view => view.destroy());
    } finally {
      this._destroyed = true;
      this._views = [];
      this._destroyListeners = [];
    }
  }
  onDestroy(callback) {
    (typeof ngDevMode === 'undefined' || ngDevMode) && warnIfDestroyed(this._destroyed);
    this._destroyListeners.push(callback);
    return () => remove(this._destroyListeners, callback);
  }
  destroy() {
    if (this._destroyed) {
      throw new RuntimeError(406, ngDevMode && 'This instance of the `ApplicationRef` has already been destroyed.');
    }
    const injector = this._injector;
    if (injector.destroy && !injector.destroyed) {
      injector.destroy();
    }
  }
  get viewCount() {
    return this._views.length;
  }
  static ɵfac = function ApplicationRef_Factory(__ngFactoryType__) {
    return new (__ngFactoryType__ || ApplicationRef)();
  };
  static ɵprov = /*@__PURE__*/ɵɵdefineService({
    token: ApplicationRef,
    factory: ApplicationRef.ɵfac
  });
}
(() => {
  (typeof ngDevMode === "undefined" || ngDevMode) && setClassMetadata(ApplicationRef, [{
    type: Service
  }], () => [], null);
})();
function normalizeBootstrapOptions(hostElementOrOptions) {
  if (hostElementOrOptions === undefined || typeof hostElementOrOptions === 'string' || hostElementOrOptions instanceof Element) {
    return {
      hostElement: hostElementOrOptions
    };
  }
  return hostElementOrOptions;
}
function warnIfDestroyed(destroyed) {
  if (destroyed) {
    console.warn(formatRuntimeError(406, 'This instance of the `ApplicationRef` has already been destroyed.'));
  }
}
function remove(list, el) {
  const index = list.indexOf(el);
  if (index > -1) {
    list.splice(index, 1);
  }
}

function onIdle(callback, injector, options) {
  const scheduler = injector.get(IdleScheduler);
  const cleanupFn = () => scheduler.remove(callback);
  scheduler.add(callback, options);
  return cleanupFn;
}
function onIdleWrapper(options) {
  return (callback, injector) => onIdle(callback, injector, options);
}
class IdleScheduler {
  buckets = new Map();
  callbackBucket = new Map();
  applicationRef = inject(ApplicationRef);
  ngZone = inject(NgZone);
  idleService = inject(IDLE_SERVICE);
  add(callback, options) {
    const key = getIdleRequestKey(options);
    this.callbackBucket.set(callback, key);
    let bucket = this.buckets.get(key);
    if (bucket == null) {
      bucket = {
        idleId: null,
        queue: new Set()
      };
      this.buckets.set(key, bucket);
    }
    bucket.queue.add(callback);
    this.scheduleBucket(bucket, options);
  }
  remove(callback) {
    const key = this.callbackBucket.get(callback);
    if (key === undefined) return;
    this.callbackBucket.delete(callback);
    const bucket = this.buckets.get(key);
    if (!bucket) return;
    bucket.queue.delete(callback);
    if (bucket.queue.size === 0) {
      this.cancelBucket(bucket);
      this.buckets.delete(key);
    }
  }
  scheduleBucket(bucket, options) {
    if (bucket.idleId !== null) {
      return;
    }
    const key = getIdleRequestKey(options);
    const callback = deadline => {
      for (const cb of bucket.queue) {
        try {
          cb();
          this.applicationRef._tick();
        } finally {
          bucket.queue.delete(cb);
          this.callbackBucket.delete(cb);
          if (deadline && deadline.timeRemaining() === 0 && !deadline.didTimeout) {
            break;
          }
        }
      }
      bucket.idleId = null;
      if (bucket.queue.size > 0) {
        this.scheduleBucket(bucket, options);
      } else if (this.buckets.get(key) === bucket) {
        this.buckets.delete(key);
      }
    };
    bucket.idleId = this.idleService.requestOnIdle(deadline => this.ngZone.run(() => callback(deadline)), options);
  }
  cancelBucket(bucket) {
    if (bucket.idleId !== null) {
      this.idleService.cancelOnIdle(bucket.idleId);
      bucket.idleId = null;
    }
  }
  ngOnDestroy() {
    for (const bucket of this.buckets.values()) {
      this.cancelBucket(bucket);
    }
    this.buckets.clear();
    this.callbackBucket.clear();
  }
  static ɵprov =
  /* @__PURE__ */
  __defineInjectable({
    token: IdleScheduler,
    providedIn: 'root',
    factory: () => new IdleScheduler()
  });
}
function getIdleRequestKey(options) {
  if (!options || options.timeout == null) {
    return '';
  }
  return `${options.timeout}`;
}

function scheduleDelayedTrigger(scheduleFn) {
  const lView = getLView();
  const tNode = getCurrentTNode();
  renderPlaceholder(lView, tNode);
  if (!shouldTriggerDeferBlock(0, lView)) return;
  const injector = lView[INJECTOR];
  const lDetails = getLDeferBlockDetails(lView, tNode);
  const cleanupFn = scheduleFn(() => triggerDeferBlock(0, lView, tNode), injector);
  storeTriggerCleanupFn(0, lDetails, cleanupFn);
}
function scheduleDelayedPrefetching(scheduleFn) {
  if (typeof ngServerMode !== 'undefined' && ngServerMode) return;
  const lView = getLView();
  const injector = lView[INJECTOR];
  const tNode = getCurrentTNode();
  const tView = lView[TVIEW$1];
  const tDetails = getTDeferBlockDetails(tView, tNode);
  if (tDetails.loadingState === DeferDependenciesLoadingState.NOT_STARTED) {
    const lDetails = getLDeferBlockDetails(lView, tNode);
    const prefetch = () => triggerPrefetching(tDetails, lView, tNode);
    const cleanupFn = scheduleFn(prefetch, injector);
    storeTriggerCleanupFn(1, lDetails, cleanupFn);
  }
}
function scheduleDelayedHydrating(scheduleFn, lView, tNode) {
  if (typeof ngServerMode !== 'undefined' && ngServerMode) return;
  const injector = lView[INJECTOR];
  const lDetails = getLDeferBlockDetails(lView, tNode);
  const ssrUniqueId = lDetails[SSR_UNIQUE_ID];
  ngDevMode && assertSsrIdDefined(ssrUniqueId);
  const cleanupFn = scheduleFn(() => triggerHydrationFromBlockName(injector, ssrUniqueId), injector);
  storeTriggerCleanupFn(2, lDetails, cleanupFn);
}
function triggerPrefetching(tDetails, lView, tNode) {
  triggerResourceLoading(tDetails, lView, tNode);
}
function triggerResourceLoading(tDetails, lView, tNode) {
  const injector = lView[INJECTOR];
  const tView = lView[TVIEW$1];
  if (tDetails.loadingState !== DeferDependenciesLoadingState.NOT_STARTED) {
    return tDetails.loadingPromise ?? Promise.resolve();
  }
  const lDetails = getLDeferBlockDetails(lView, tNode);
  const primaryBlockTNode = getPrimaryBlockTNode(tView, tDetails);
  tDetails.loadingState = DeferDependenciesLoadingState.IN_PROGRESS;
  invokeTriggerCleanupFns(1, lDetails);
  let dependenciesFn = tDetails.dependencyResolverFn;
  if (ngDevMode) {
    const deferDependencyInterceptor = injector.get(DEFER_BLOCK_DEPENDENCY_INTERCEPTOR, null, {
      optional: true
    });
    if (deferDependencyInterceptor) {
      dependenciesFn = deferDependencyInterceptor.intercept(dependenciesFn);
    }
  }
  const removeTask = injector.get(PendingTasks).add();
  if (!dependenciesFn) {
    tDetails.loadingPromise = Promise.resolve().then(() => {
      tDetails.loadingPromise = null;
      tDetails.loadingState = DeferDependenciesLoadingState.COMPLETE;
      removeTask();
    });
    return tDetails.loadingPromise;
  }
  tDetails.loadingPromise = Promise.allSettled(dependenciesFn()).then(results => {
    let failed = false;
    let failedReason = null;
    const directiveDefs = [];
    const pipeDefs = [];
    for (let i = 0; i < results.length; i++) {
      const result = results[i];
      if (result.status === 'fulfilled') {
        const dependency = result.value;
        const directiveDef = getComponentDef(dependency) || getDirectiveDef(dependency);
        if (directiveDef) {
          directiveDefs.push(directiveDef);
        } else {
          const pipeDef = getPipeDef$1(dependency);
          if (pipeDef) {
            pipeDefs.push(pipeDef);
          }
        }
      } else {
        failed = true;
        failedReason = result.reason instanceof Error ? result.reason : new Error(String(result.reason));
        break;
      }
    }
    if (failed) {
      tDetails.loadingState = DeferDependenciesLoadingState.FAILED;
      if (tDetails.errorTmplIndex === null) {
        const templateLocation = ngDevMode ? getTemplateLocationDetails(lView) : '';
        let errorMsg = '';
        if (ngDevMode) {
          errorMsg = 'Loading dependencies for `@defer` block failed, ' + `but no \`@error\` block was configured${templateLocation}. ` + 'Consider using the `@error` block to render an error state.';
          const depsFn = tDetails.dependencyResolverFn;
          const errorReason = failedReason?.message;
          if (depsFn) {
            errorMsg += `\n\nAngular tried to invoke the following dependency function (compiler-generated):\n` + `\`\`\`\n${depsFn.toString()}\n\`\`\``;
          }
          if (errorReason) {
            errorMsg += depsFn ? `\n\nbut it resulted in the following error:\n\n${errorReason}` : `\n\nThe loading resulted in the following error:\n\n${errorReason}`;
          }
        }
        const error = new RuntimeError(-750, errorMsg);
        handleUncaughtError(lView, error);
      }
    } else {
      tDetails.loadingState = DeferDependenciesLoadingState.COMPLETE;
      const primaryBlockTView = primaryBlockTNode.tView;
      if (directiveDefs.length > 0) {
        primaryBlockTView.directiveRegistry = addDepsToRegistry(primaryBlockTView.directiveRegistry, directiveDefs);
        const directiveTypes = directiveDefs.map(def => def.type);
        const providers = internalImportProvidersFrom(false, ...directiveTypes);
        tDetails.providers = providers;
      }
      if (pipeDefs.length > 0) {
        primaryBlockTView.pipeRegistry = addDepsToRegistry(primaryBlockTView.pipeRegistry, pipeDefs);
      }
    }
  });
  return tDetails.loadingPromise.finally(() => {
    tDetails.loadingPromise = null;
    removeTask();
  });
}
function triggerDeferBlock(triggerType, lView, tNode) {
  const tView = lView[TVIEW$1];
  const lContainer = lView[tNode.index];
  ngDevMode && assertLContainer(lContainer);
  if (!shouldTriggerDeferBlock(triggerType, lView)) return;
  const lDetails = getLDeferBlockDetails(lView, tNode);
  const tDetails = getTDeferBlockDetails(tView, tNode);
  invokeAllTriggerCleanupFns(lDetails);
  switch (tDetails.loadingState) {
    case DeferDependenciesLoadingState.NOT_STARTED:
      renderDeferBlockState(DeferBlockState.Loading, tNode, lContainer);
      triggerResourceLoading(tDetails, lView, tNode);
      if (tDetails.loadingState === DeferDependenciesLoadingState.IN_PROGRESS) {
        renderDeferStateAfterResourceLoading(tDetails, tNode, lContainer);
      }
      break;
    case DeferDependenciesLoadingState.IN_PROGRESS:
      renderDeferBlockState(DeferBlockState.Loading, tNode, lContainer);
      renderDeferStateAfterResourceLoading(tDetails, tNode, lContainer);
      break;
    case DeferDependenciesLoadingState.COMPLETE:
      ngDevMode && assertDeferredDependenciesLoaded(tDetails);
      renderDeferBlockState(DeferBlockState.Complete, tNode, lContainer);
      break;
    case DeferDependenciesLoadingState.FAILED:
      renderDeferBlockState(DeferBlockState.Error, tNode, lContainer);
      break;
    default:
      if (ngDevMode) {
        throwError('Unknown defer block state');
      }
  }
}
async function triggerHydrationFromBlockName(injector, blockName, replayQueuedEventsFn) {
  const dehydratedBlockRegistry = injector.get(DEHYDRATED_BLOCK_REGISTRY);
  const blocksBeingHydrated = dehydratedBlockRegistry.hydrating;
  if (blocksBeingHydrated.has(blockName)) {
    return;
  }
  const {
    parentBlockPromise,
    hydrationQueue
  } = getParentBlockHydrationQueue(blockName, injector);
  if (hydrationQueue.length === 0) return;
  if (parentBlockPromise !== null) {
    hydrationQueue.shift();
  }
  populateHydratingStateForQueue(dehydratedBlockRegistry, hydrationQueue);
  if (parentBlockPromise !== null) {
    await parentBlockPromise;
  }
  const topmostParentBlock = hydrationQueue[0];
  if (dehydratedBlockRegistry.has(topmostParentBlock)) {
    await triggerHydrationForBlockQueue(injector, hydrationQueue, replayQueuedEventsFn);
  } else {
    dehydratedBlockRegistry.awaitParentBlock(topmostParentBlock, async () => await triggerHydrationForBlockQueue(injector, hydrationQueue, replayQueuedEventsFn));
  }
}
async function triggerHydrationForBlockQueue(injector, hydrationQueue, replayQueuedEventsFn) {
  const dehydratedBlockRegistry = injector.get(DEHYDRATED_BLOCK_REGISTRY);
  const blocksBeingHydrated = dehydratedBlockRegistry.hydrating;
  const pendingTasks = injector.get(PendingTasksInternal);
  const taskId = pendingTasks.add();
  for (let blockQueueIdx = 0; blockQueueIdx < hydrationQueue.length; blockQueueIdx++) {
    const dehydratedBlockId = hydrationQueue[blockQueueIdx];
    const dehydratedDeferBlock = dehydratedBlockRegistry.get(dehydratedBlockId);
    if (dehydratedDeferBlock != null) {
      await triggerResourceLoadingForHydration(dehydratedDeferBlock);
      await nextRender(injector);
      if (deferBlockHasErrored(dehydratedDeferBlock)) {
        removeDehydratedViewList(dehydratedDeferBlock);
        cleanupRemainingHydrationQueue(hydrationQueue.slice(blockQueueIdx), dehydratedBlockRegistry);
        break;
      }
      blocksBeingHydrated.get(dehydratedBlockId).resolve();
    } else {
      cleanupParentContainer(blockQueueIdx, hydrationQueue, dehydratedBlockRegistry);
      cleanupRemainingHydrationQueue(hydrationQueue.slice(blockQueueIdx), dehydratedBlockRegistry);
      break;
    }
  }
  const lastBlockName = hydrationQueue[hydrationQueue.length - 1];
  await blocksBeingHydrated.get(lastBlockName)?.promise;
  pendingTasks.remove(taskId);
  if (replayQueuedEventsFn) {
    replayQueuedEventsFn(hydrationQueue);
  }
  const appRef = injector.get(ApplicationRef);
  const lastDeferBlock = dehydratedBlockRegistry.get(lastBlockName);
  if (pendingTasks.hasPendingTasks) {
    await appRef.whenStable();
    if (appRef.destroyed) {
      return;
    }
  }
  cleanupHydratedDeferBlocks(lastDeferBlock, hydrationQueue, dehydratedBlockRegistry, appRef);
}
function deferBlockHasErrored(deferBlock) {
  return getLDeferBlockDetails(deferBlock.lView, deferBlock.tNode)[DEFER_BLOCK_STATE] === DeferBlockState.Error;
}
function cleanupParentContainer(currentBlockIdx, hydrationQueue, dehydratedBlockRegistry) {
  const parentDeferBlockIdx = currentBlockIdx - 1;
  const parentDeferBlock = parentDeferBlockIdx > -1 ? dehydratedBlockRegistry.get(hydrationQueue[parentDeferBlockIdx]) : null;
  if (parentDeferBlock) {
    cleanupLContainer(parentDeferBlock.lContainer);
  }
}
function cleanupRemainingHydrationQueue(hydrationQueue, dehydratedBlockRegistry) {
  const blocksBeingHydrated = dehydratedBlockRegistry.hydrating;
  for (const dehydratedBlockId of hydrationQueue) {
    blocksBeingHydrated.get(dehydratedBlockId)?.reject();
  }
  dehydratedBlockRegistry.cleanup(hydrationQueue);
}
function populateHydratingStateForQueue(registry, queue) {
  for (let blockId of queue) {
    registry.hydrating.set(blockId, promiseWithResolvers());
  }
}
function nextRender(injector) {
  return new Promise(resolveFn => afterNextRender(resolveFn, {
    injector
  }));
}
async function triggerResourceLoadingForHydration(dehydratedBlock) {
  const {
    tNode,
    lView
  } = dehydratedBlock;
  const lDetails = getLDeferBlockDetails(lView, tNode);
  return new Promise(resolve => {
    onDeferBlockCompletion(lDetails, resolve);
    triggerDeferBlock(2, lView, tNode);
  });
}
function onDeferBlockCompletion(lDetails, callback) {
  if (!Array.isArray(lDetails[ON_COMPLETE_FNS])) {
    lDetails[ON_COMPLETE_FNS] = [];
  }
  lDetails[ON_COMPLETE_FNS].push(callback);
}
function shouldAttachTrigger(triggerType, lView, tNode) {
  if (triggerType === 0) {
    return shouldAttachRegularTrigger(lView, tNode);
  } else if (triggerType === 2) {
    return !shouldAttachRegularTrigger(lView, tNode);
  }
  return !(typeof ngServerMode !== 'undefined' && ngServerMode);
}
function hasHydrateTriggers(flags) {
  return flags != null && (flags & 1) === 1;
}
function shouldAttachRegularTrigger(lView, tNode) {
  const injector = lView[INJECTOR];
  const tDetails = getTDeferBlockDetails(lView[TVIEW$1], tNode);
  const incrementalHydrationEnabled = isIncrementalHydrationEnabled(injector);
  const _hasHydrateTriggers = hasHydrateTriggers(tDetails.flags);
  if (typeof ngServerMode !== 'undefined' && ngServerMode) {
    return !incrementalHydrationEnabled || !_hasHydrateTriggers;
  }
  const lDetails = getLDeferBlockDetails(lView, tNode);
  const wasServerSideRendered = lDetails[SSR_UNIQUE_ID] !== null;
  if (_hasHydrateTriggers && wasServerSideRendered && incrementalHydrationEnabled) {
    return false;
  }
  return true;
}
function getHydrateTriggers(tView, tNode) {
  const tDetails = getTDeferBlockDetails(tView, tNode);
  return tDetails.hydrateTriggers ??= new Map();
}
function processAndInitTriggers(injector, blockData, nodes) {
  const idleElements = [];
  const timerElements = [];
  const viewportElements = [];
  const immediateElements = [];
  for (let [blockId, blockSummary] of blockData) {
    const commentNode = nodes.get(blockId);
    if (commentNode !== undefined) {
      const numRootNodes = blockSummary.data[NUM_ROOT_NODES];
      let currentNode = commentNode;
      for (let i = 0; i < numRootNodes; i++) {
        currentNode = currentNode.previousSibling;
        if (currentNode.nodeType !== Node.ELEMENT_NODE) {
          continue;
        }
        const elementTrigger = {
          el: currentNode,
          blockName: blockId
        };
        if (blockSummary.hydrate.idle) {
          idleElements.push(elementTrigger);
        }
        if (blockSummary.hydrate.immediate) {
          immediateElements.push(elementTrigger);
        }
        if (blockSummary.hydrate.timer !== null) {
          elementTrigger.delay = blockSummary.hydrate.timer;
          timerElements.push(elementTrigger);
        }
        if (blockSummary.hydrate.viewport) {
          if (typeof blockSummary.hydrate.viewport !== 'boolean') {
            elementTrigger.intersectionObserverOptions = blockSummary.hydrate.viewport;
          }
          viewportElements.push(elementTrigger);
        }
      }
    }
  }
  setIdleTriggers(injector, idleElements);
  setImmediateTriggers(injector, immediateElements);
  setViewportTriggers(injector, viewportElements);
  setTimerTriggers(injector, timerElements);
}
function setIdleTriggers(injector, elementTriggers) {
  for (const elementTrigger of elementTriggers) {
    const registry = injector.get(DEHYDRATED_BLOCK_REGISTRY);
    const onInvoke = () => triggerHydrationFromBlockName(injector, elementTrigger.blockName);
    const cleanupFn = onIdle(onInvoke, injector);
    registry.addCleanupFn(elementTrigger.blockName, cleanupFn);
  }
}
function setViewportTriggers(injector, elementTriggers) {
  if (elementTriggers.length > 0) {
    const registry = injector.get(DEHYDRATED_BLOCK_REGISTRY);
    for (let elementTrigger of elementTriggers) {
      const cleanupFn = onViewportWrapper(elementTrigger.el, () => triggerHydrationFromBlockName(injector, elementTrigger.blockName), injector, elementTrigger.intersectionObserverOptions);
      registry.addCleanupFn(elementTrigger.blockName, cleanupFn);
    }
  }
}
function setTimerTriggers(injector, elementTriggers) {
  for (const elementTrigger of elementTriggers) {
    const registry = injector.get(DEHYDRATED_BLOCK_REGISTRY);
    const onInvoke = () => triggerHydrationFromBlockName(injector, elementTrigger.blockName);
    const timerFn = onTimer(elementTrigger.delay);
    const cleanupFn = timerFn(onInvoke, injector);
    registry.addCleanupFn(elementTrigger.blockName, cleanupFn);
  }
}
function setImmediateTriggers(injector, elementTriggers) {
  for (const elementTrigger of elementTriggers) {
    triggerHydrationFromBlockName(injector, elementTrigger.blockName);
  }
}

let _hmrWarningProduced = false;
function logHmrWarning(injector) {
  if (!_hmrWarningProduced) {
    _hmrWarningProduced = true;
    const console = injector.get(Console);
    console.log(formatRuntimeError(-751, 'Angular has detected that this application contains `@defer` blocks ' + 'and the hot module replacement (HMR) mode is enabled. All `@defer` ' + 'block dependencies will be loaded eagerly.'));
  }
}
function ɵɵdefer(index, primaryTmplIndex, dependencyResolverFn, loadingTmplIndex, placeholderTmplIndex, errorTmplIndex, loadingConfigIndex, placeholderConfigIndex, enableTimerScheduling, flags) {
  const lView = getLView();
  const tView = getTView();
  const adjustedIndex = index + HEADER_OFFSET;
  const tNode = declareNoDirectiveHostTemplate(lView, tView, index, null, 0, 0);
  const injector = lView[INJECTOR];
  const incrementalHydrationEnabled = isIncrementalHydrationEnabled(injector);
  if (tView.firstCreatePass) {
    performanceMarkFeature('NgDefer');
    if (ngDevMode) {
      if (typeof ngHmrMode !== 'undefined' && ngHmrMode) {
        logHmrWarning(injector);
      }
      if (hasHydrateTriggers(flags) && !incrementalHydrationEnabled) {
        warnIncrementalHydrationNotConfigured();
      }
    }
    const tDetails = {
      primaryTmplIndex,
      loadingTmplIndex: loadingTmplIndex ?? null,
      placeholderTmplIndex: placeholderTmplIndex ?? null,
      errorTmplIndex: errorTmplIndex ?? null,
      placeholderBlockConfig: null,
      loadingBlockConfig: null,
      dependencyResolverFn: dependencyResolverFn ?? null,
      loadingState: DeferDependenciesLoadingState.NOT_STARTED,
      loadingPromise: null,
      providers: null,
      hydrateTriggers: null,
      debug: null,
      flags: flags ?? 0
    };
    enableTimerScheduling?.(tView, tDetails, placeholderConfigIndex, loadingConfigIndex);
    setTDeferBlockDetails(tView, adjustedIndex, tDetails);
  }
  const lContainer = lView[adjustedIndex];
  populateDehydratedViewsInLContainer(lContainer, tNode, lView);
  let ssrBlockState = null;
  let ssrUniqueId = null;
  if (lContainer[DEHYDRATED_VIEWS]?.length > 0) {
    const info = lContainer[DEHYDRATED_VIEWS][0].data;
    ssrUniqueId = info[DEFER_BLOCK_ID] ?? null;
    ssrBlockState = info[DEFER_BLOCK_STATE$1];
  }
  const lDetails = [null, DeferBlockInternalState.Initial, null, null, null, null, ssrUniqueId, ssrBlockState, null, null];
  setLDeferBlockDetails(lView, adjustedIndex, lDetails);
  let registry = null;
  if (ssrUniqueId !== null && incrementalHydrationEnabled) {
    registry = injector.get(DEHYDRATED_BLOCK_REGISTRY);
    registry.add(ssrUniqueId, {
      lView,
      tNode,
      lContainer
    });
  }
  const onLViewDestroy = () => {
    invokeAllTriggerCleanupFns(lDetails);
    if (ssrUniqueId !== null) {
      registry?.cleanup([ssrUniqueId]);
    }
  };
  storeTriggerCleanupFn(0, lDetails, () => removeLViewOnDestroy(lView, onLViewDestroy));
  storeLViewOnDestroy(lView, onLViewDestroy);
}
function ɵɵdeferWhen(rawValue) {
  const lView = getLView();
  const tNode = getSelectedTNode();
  if (ngDevMode) {
    trackTriggerForDebugging(lView[TVIEW$1], tNode, 'when <expression>');
  }
  if (!shouldAttachTrigger(0, lView, tNode)) return;
  const bindingIndex = nextBindingIndex();
  if (bindingUpdated(lView, bindingIndex, rawValue)) {
    const prevConsumer = setActiveConsumer(null);
    try {
      const value = Boolean(rawValue);
      const lDetails = getLDeferBlockDetails(lView, tNode);
      const renderedState = lDetails[DEFER_BLOCK_STATE];
      if (value === false && renderedState === DeferBlockInternalState.Initial) {
        renderPlaceholder(lView, tNode);
      } else if (value === true && (renderedState === DeferBlockInternalState.Initial || renderedState === DeferBlockState.Placeholder)) {
        triggerDeferBlock(0, lView, tNode);
      }
    } finally {
      setActiveConsumer(prevConsumer);
    }
  }
}
function ɵɵdeferPrefetchWhen(rawValue) {
  const lView = getLView();
  const tNode = getSelectedTNode();
  if (ngDevMode) {
    trackTriggerForDebugging(lView[TVIEW$1], tNode, 'prefetch when <expression>');
  }
  if (!shouldAttachTrigger(1, lView, tNode)) return;
  const bindingIndex = nextBindingIndex();
  if (bindingUpdated(lView, bindingIndex, rawValue)) {
    const prevConsumer = setActiveConsumer(null);
    try {
      const value = Boolean(rawValue);
      const tView = lView[TVIEW$1];
      const tDetails = getTDeferBlockDetails(tView, tNode);
      if (value === true && tDetails.loadingState === DeferDependenciesLoadingState.NOT_STARTED) {
        triggerPrefetching(tDetails, lView, tNode);
      }
    } finally {
      setActiveConsumer(prevConsumer);
    }
  }
}
function ɵɵdeferHydrateWhen(rawValue) {
  const lView = getLView();
  const tNode = getSelectedTNode();
  if (ngDevMode) {
    trackTriggerForDebugging(lView[TVIEW$1], tNode, 'hydrate when <expression>');
  }
  if (!shouldAttachTrigger(2, lView, tNode)) return;
  const bindingIndex = nextBindingIndex();
  const tView = getTView();
  const hydrateTriggers = getHydrateTriggers(tView, tNode);
  hydrateTriggers.set(6, null);
  if (bindingUpdated(lView, bindingIndex, rawValue)) {
    if (typeof ngServerMode !== 'undefined' && ngServerMode) {
      triggerDeferBlock(2, lView, tNode);
    } else {
      const injector = lView[INJECTOR];
      const prevConsumer = setActiveConsumer(null);
      try {
        const value = Boolean(rawValue);
        if (value === true) {
          const lDetails = getLDeferBlockDetails(lView, tNode);
          const ssrUniqueId = lDetails[SSR_UNIQUE_ID];
          ngDevMode && assertSsrIdDefined(ssrUniqueId);
          triggerHydrationFromBlockName(injector, ssrUniqueId);
        }
      } finally {
        setActiveConsumer(prevConsumer);
      }
    }
  }
}
function ɵɵdeferHydrateNever() {
  const lView = getLView();
  const tNode = getCurrentTNode();
  if (ngDevMode) {
    trackTriggerForDebugging(lView[TVIEW$1], tNode, 'hydrate never');
  }
  if (!shouldAttachTrigger(2, lView, tNode)) return;
  const hydrateTriggers = getHydrateTriggers(getTView(), tNode);
  hydrateTriggers.set(7, null);
  if (typeof ngServerMode !== 'undefined' && ngServerMode) {
    triggerDeferBlock(2, lView, tNode);
  }
}
function ɵɵdeferOnIdle(timeout) {
  const lView = getLView();
  const tNode = getCurrentTNode();
  if (ngDevMode) {
    const expression = timeout ? `on idle(${timeout})` : 'on idle';
    trackTriggerForDebugging(lView[TVIEW$1], tNode, expression);
  }
  if (!shouldAttachTrigger(0, lView, tNode)) return;
  scheduleDelayedTrigger(onIdleWrapper({
    timeout
  }));
}
function ɵɵdeferPrefetchOnIdle(timeout) {
  const lView = getLView();
  const tNode = getCurrentTNode();
  if (ngDevMode) {
    const expression = timeout ? `prefetch on idle(${timeout})` : 'prefetch on idle';
    trackTriggerForDebugging(lView[TVIEW$1], tNode, expression);
  }
  if (!shouldAttachTrigger(1, lView, tNode)) return;
  scheduleDelayedPrefetching(onIdleWrapper({
    timeout
  }));
}
function ɵɵdeferHydrateOnIdle(timeout) {
  const lView = getLView();
  const tNode = getCurrentTNode();
  if (ngDevMode) {
    const expression = timeout ? `hydrate on idle(${timeout})` : 'hydrate on idle';
    trackTriggerForDebugging(lView[TVIEW$1], tNode, expression);
  }
  if (!shouldAttachTrigger(2, lView, tNode)) return;
  const hydrateTriggers = getHydrateTriggers(getTView(), tNode);
  hydrateTriggers.set(0, null);
  if (typeof ngServerMode !== 'undefined' && ngServerMode) {
    triggerDeferBlock(2, lView, tNode);
  } else {
    scheduleDelayedHydrating(onIdleWrapper({
      timeout
    }), lView, tNode);
  }
}
function ɵɵdeferOnImmediate() {
  const lView = getLView();
  const tNode = getCurrentTNode();
  if (ngDevMode) {
    trackTriggerForDebugging(lView[TVIEW$1], tNode, 'on immediate');
  }
  if (!shouldAttachTrigger(0, lView, tNode)) return;
  const tDetails = getTDeferBlockDetails(lView[TVIEW$1], tNode);
  if (tDetails.loadingTmplIndex === null) {
    renderPlaceholder(lView, tNode);
  }
  triggerDeferBlock(0, lView, tNode);
}
function ɵɵdeferPrefetchOnImmediate() {
  const lView = getLView();
  const tNode = getCurrentTNode();
  if (ngDevMode) {
    trackTriggerForDebugging(lView[TVIEW$1], tNode, 'prefetch on immediate');
  }
  if (!shouldAttachTrigger(1, lView, tNode)) return;
  const tView = lView[TVIEW$1];
  const tDetails = getTDeferBlockDetails(tView, tNode);
  if (tDetails.loadingState === DeferDependenciesLoadingState.NOT_STARTED) {
    triggerResourceLoading(tDetails, lView, tNode);
  }
}
function ɵɵdeferHydrateOnImmediate() {
  const lView = getLView();
  const tNode = getCurrentTNode();
  if (ngDevMode) {
    trackTriggerForDebugging(lView[TVIEW$1], tNode, 'hydrate on immediate');
  }
  if (!shouldAttachTrigger(2, lView, tNode)) return;
  const hydrateTriggers = getHydrateTriggers(getTView(), tNode);
  hydrateTriggers.set(1, null);
  if (typeof ngServerMode !== 'undefined' && ngServerMode) {
    triggerDeferBlock(2, lView, tNode);
  } else {
    const injector = lView[INJECTOR];
    const lDetails = getLDeferBlockDetails(lView, tNode);
    const ssrUniqueId = lDetails[SSR_UNIQUE_ID];
    ngDevMode && assertSsrIdDefined(ssrUniqueId);
    triggerHydrationFromBlockName(injector, ssrUniqueId);
  }
}
function ɵɵdeferOnTimer(delay) {
  const lView = getLView();
  const tNode = getCurrentTNode();
  if (ngDevMode) {
    trackTriggerForDebugging(lView[TVIEW$1], tNode, `on timer(${delay}ms)`);
  }
  if (!shouldAttachTrigger(0, lView, tNode)) return;
  scheduleDelayedTrigger(onTimer(delay));
}
function ɵɵdeferPrefetchOnTimer(delay) {
  const lView = getLView();
  const tNode = getCurrentTNode();
  if (ngDevMode) {
    trackTriggerForDebugging(lView[TVIEW$1], tNode, `prefetch on timer(${delay}ms)`);
  }
  if (!shouldAttachTrigger(1, lView, tNode)) return;
  scheduleDelayedPrefetching(onTimer(delay));
}
function ɵɵdeferHydrateOnTimer(delay) {
  const lView = getLView();
  const tNode = getCurrentTNode();
  if (ngDevMode) {
    trackTriggerForDebugging(lView[TVIEW$1], tNode, `hydrate on timer(${delay}ms)`);
  }
  if (!shouldAttachTrigger(2, lView, tNode)) return;
  const hydrateTriggers = getHydrateTriggers(getTView(), tNode);
  hydrateTriggers.set(5, {
    type: 5,
    delay
  });
  if (typeof ngServerMode !== 'undefined' && ngServerMode) {
    triggerDeferBlock(2, lView, tNode);
  } else {
    scheduleDelayedHydrating(onTimer(delay), lView, tNode);
  }
}
function ɵɵdeferOnHover(triggerIndex, walkUpTimes) {
  const lView = getLView();
  const tNode = getCurrentTNode();
  if (ngDevMode) {
    trackTriggerForDebugging(lView[TVIEW$1], tNode, `on hover${walkUpTimes === -1 ? '' : '(<target>)'}`);
  }
  if (!shouldAttachTrigger(0, lView, tNode)) return;
  renderPlaceholder(lView, tNode);
  if (!(typeof ngServerMode !== 'undefined' && ngServerMode)) {
    registerDomTrigger(lView, tNode, triggerIndex, walkUpTimes, onHover, () => triggerDeferBlock(0, lView, tNode), 0);
  }
}
function ɵɵdeferPrefetchOnHover(triggerIndex, walkUpTimes) {
  const lView = getLView();
  const tNode = getCurrentTNode();
  if (ngDevMode) {
    trackTriggerForDebugging(lView[TVIEW$1], tNode, `prefetch on hover${walkUpTimes === -1 ? '' : '(<target>)'}`);
  }
  if (!shouldAttachTrigger(1, lView, tNode)) return;
  const tView = lView[TVIEW$1];
  const tDetails = getTDeferBlockDetails(tView, tNode);
  if (tDetails.loadingState === DeferDependenciesLoadingState.NOT_STARTED) {
    registerDomTrigger(lView, tNode, triggerIndex, walkUpTimes, onHover, () => triggerPrefetching(tDetails, lView, tNode), 1);
  }
}
function ɵɵdeferHydrateOnHover() {
  const lView = getLView();
  const tNode = getCurrentTNode();
  if (ngDevMode) {
    trackTriggerForDebugging(lView[TVIEW$1], tNode, 'hydrate on hover');
  }
  if (!shouldAttachTrigger(2, lView, tNode)) return;
  const hydrateTriggers = getHydrateTriggers(getTView(), tNode);
  hydrateTriggers.set(4, null);
  if (typeof ngServerMode !== 'undefined' && ngServerMode) {
    triggerDeferBlock(2, lView, tNode);
  }
}
function ɵɵdeferOnInteraction(triggerIndex, walkUpTimes) {
  const lView = getLView();
  const tNode = getCurrentTNode();
  if (ngDevMode) {
    trackTriggerForDebugging(lView[TVIEW$1], tNode, `on interaction${walkUpTimes === -1 ? '' : '(<target>)'}`);
  }
  if (!shouldAttachTrigger(0, lView, tNode)) return;
  renderPlaceholder(lView, tNode);
  if (!(typeof ngServerMode !== 'undefined' && ngServerMode)) {
    registerDomTrigger(lView, tNode, triggerIndex, walkUpTimes, onInteraction, () => triggerDeferBlock(0, lView, tNode), 0);
  }
}
function ɵɵdeferPrefetchOnInteraction(triggerIndex, walkUpTimes) {
  const lView = getLView();
  const tNode = getCurrentTNode();
  if (ngDevMode) {
    trackTriggerForDebugging(lView[TVIEW$1], tNode, `prefetch on interaction${walkUpTimes === -1 ? '' : '(<target>)'}`);
  }
  if (!shouldAttachTrigger(1, lView, tNode)) return;
  const tView = lView[TVIEW$1];
  const tDetails = getTDeferBlockDetails(tView, tNode);
  if (tDetails.loadingState === DeferDependenciesLoadingState.NOT_STARTED) {
    registerDomTrigger(lView, tNode, triggerIndex, walkUpTimes, onInteraction, () => triggerPrefetching(tDetails, lView, tNode), 1);
  }
}
function ɵɵdeferHydrateOnInteraction() {
  const lView = getLView();
  const tNode = getCurrentTNode();
  if (ngDevMode) {
    trackTriggerForDebugging(lView[TVIEW$1], tNode, 'hydrate on interaction');
  }
  if (!shouldAttachTrigger(2, lView, tNode)) return;
  const hydrateTriggers = getHydrateTriggers(getTView(), tNode);
  hydrateTriggers.set(3, null);
  if (typeof ngServerMode !== 'undefined' && ngServerMode) {
    triggerDeferBlock(2, lView, tNode);
  }
}
function ɵɵdeferOnViewport(triggerIndex, walkUpTimes, options) {
  const lView = getLView();
  const tNode = getCurrentTNode();
  if (ngDevMode) {
    const args = [];
    if (walkUpTimes !== undefined && walkUpTimes !== -1) {
      args.push('<target>');
    }
    if (options) {
      args.push(JSON.stringify(options));
    }
    trackTriggerForDebugging(lView[TVIEW$1], tNode, `on viewport${args.length === 0 ? '' : `(${args.join(', ')})`}`);
  }
  if (!shouldAttachTrigger(0, lView, tNode)) return;
  renderPlaceholder(lView, tNode);
  if (!(typeof ngServerMode !== 'undefined' && ngServerMode)) {
    registerDomTrigger(lView, tNode, triggerIndex, walkUpTimes, onViewportWrapper, () => triggerDeferBlock(0, lView, tNode), 0, options);
  }
}
function ɵɵdeferPrefetchOnViewport(triggerIndex, walkUpTimes, options) {
  const lView = getLView();
  const tNode = getCurrentTNode();
  if (ngDevMode) {
    const args = [];
    if (walkUpTimes !== undefined && walkUpTimes !== -1) {
      args.push('<target>');
    }
    if (options) {
      args.push(JSON.stringify(options));
    }
    trackTriggerForDebugging(lView[TVIEW$1], tNode, `prefetch on viewport${args.length === 0 ? '' : `(${args.join(', ')})`}`);
  }
  if (!shouldAttachTrigger(1, lView, tNode)) return;
  const tView = lView[TVIEW$1];
  const tDetails = getTDeferBlockDetails(tView, tNode);
  if (tDetails.loadingState === DeferDependenciesLoadingState.NOT_STARTED) {
    registerDomTrigger(lView, tNode, triggerIndex, walkUpTimes, onViewportWrapper, () => triggerPrefetching(tDetails, lView, tNode), 1, options);
  }
}
function ɵɵdeferHydrateOnViewport(options) {
  const lView = getLView();
  const tNode = getCurrentTNode();
  if (ngDevMode) {
    trackTriggerForDebugging(lView[TVIEW$1], tNode, `hydrate on viewport${options ? `(${JSON.stringify(options)})` : ''}`);
  }
  if (!shouldAttachTrigger(2, lView, tNode)) return;
  const hydrateTriggers = getHydrateTriggers(getTView(), tNode);
  hydrateTriggers.set(2, options ? {
    type: 2,
    intersectionObserverOptions: options
  } : null);
  if (typeof ngServerMode !== 'undefined' && ngServerMode) {
    triggerDeferBlock(2, lView, tNode);
  }
}

function ɵɵariaProperty(name, value) {
  const lView = getLView();
  const bindingIndex = nextBindingIndex();
  if (bindingUpdated(lView, bindingIndex, value)) {
    const tView = getTView();
    const tNode = getSelectedTNode();
    const hasSetInput = setAllInputsForProperty(tNode, tView, lView, name, value);
    if (hasSetInput) {
      isComponentHost(tNode) && markDirtyIfOnPush(lView, tNode.index);
      ngDevMode && setNgReflectProperties(lView, tView, tNode, name, value);
    } else {
      ngDevMode && assertTNodeType(tNode, 2);
      const element = getNativeByTNode(tNode, lView);
      setElementAttribute(lView[RENDERER], element, null, tNode.value, name, value, null);
    }
    ngDevMode && storePropertyBindingMetadata(tView.data, tNode, name, bindingIndex);
  }
  return ɵɵariaProperty;
}

function ɵɵattribute(name, value, sanitizer, namespace) {
  const lView = getLView();
  const bindingIndex = nextBindingIndex();
  if (bindingUpdated(lView, bindingIndex, value)) {
    const tView = getTView();
    const tNode = getSelectedTNode();
    elementAttributeInternal(tNode, lView, name, value, sanitizer, namespace);
    ngDevMode && storePropertyBindingMetadata(tView.data, tNode, 'attr.' + name, bindingIndex);
  }
  return ɵɵattribute;
}

function ɵɵanimateEnter(value) {
  performanceMarkFeature('NgAnimateEnter');
  if (typeof ngServerMode !== 'undefined' && ngServerMode || !areAnimationSupported) {
    return ɵɵanimateEnter;
  }
  ngDevMode && assertAnimationTypes(value, 'animate.enter');
  const lView = getLView();
  if (areAnimationsDisabled(lView)) {
    return ɵɵanimateEnter;
  }
  const tNode = getCurrentTNode();
  const ngZone = lView[INJECTOR].get(NgZone);
  enableAnimationRuntimeSupport();
  addAnimationToLView(getLViewEnterAnimations(lView), tNode, () => runEnterAnimation(lView, tNode, value, ngZone));
  initializeAnimationQueueScheduler(lView[INJECTOR]);
  queueEnterAnimations(lView[INJECTOR], getLViewEnterAnimations(lView));
  return ɵɵanimateEnter;
}
function runEnterAnimation(lView, tNode, value, ngZone) {
  const nativeElement = getNativeByTNode(tNode, lView);
  ngDevMode && assertElementNodes(nativeElement, 'animate.enter');
  const renderer = lView[RENDERER];
  const activeClasses = getClassListFromValue(value);
  const cleanupFns = [];
  let hasCompleted = false;
  const handleEnterAnimationStart = event => {
    if (getEventTarget(event) !== nativeElement) return;
    const eventName = event instanceof AnimationEvent ? 'animationend' : 'transitionend';
    ngZone.runOutsideAngular(() => {
      renderer.listen(nativeElement, eventName, handleEnterAnimationEnd);
    });
  };
  const handleEnterAnimationEnd = event => {
    if (getEventTarget(event) !== nativeElement) return;
    if (isLongestAnimation(event, nativeElement)) {
      hasCompleted = true;
    }
    enterAnimationEnd(event, nativeElement, renderer);
  };
  if (activeClasses && activeClasses.length > 0) {
    ngZone.runOutsideAngular(() => {
      cleanupFns.push(renderer.listen(nativeElement, 'animationstart', handleEnterAnimationStart));
      cleanupFns.push(renderer.listen(nativeElement, 'transitionstart', handleEnterAnimationStart));
    });
    trackEnterClasses(nativeElement, activeClasses, cleanupFns);
    addClasses(renderer, nativeElement, activeClasses);
    ngZone.runOutsideAngular(() => {
      requestAnimationFrame(() => {
        if (hasCompleted) return;
        determineLongestAnimation(nativeElement, longestAnimations, areAnimationSupported);
        if (!longestAnimations.has(nativeElement)) {
          removeClasses(renderer, nativeElement, activeClasses);
          cleanupEnterClassData(nativeElement);
        }
      });
    });
  }
}
function enterAnimationEnd(event, nativeElement, renderer) {
  const elementData = enterClassMap.get(nativeElement);
  if (getEventTarget(event) !== nativeElement || !elementData) return;
  if (isLongestAnimation(event, nativeElement)) {
    event.stopPropagation();
    removeClasses(renderer, nativeElement, elementData.classList);
    cleanupEnterClassData(nativeElement);
  }
}
function ɵɵanimateEnterListener(value) {
  performanceMarkFeature('NgAnimateEnter');
  if (typeof ngServerMode !== 'undefined' && ngServerMode || !areAnimationSupported) {
    return ɵɵanimateEnterListener;
  }
  ngDevMode && assertAnimationTypes(value, 'animate.enter');
  const lView = getLView();
  if (areAnimationsDisabled(lView)) {
    return ɵɵanimateEnterListener;
  }
  const tNode = getCurrentTNode();
  enableAnimationRuntimeSupport();
  addAnimationToLView(getLViewEnterAnimations(lView), tNode, () => runEnterAnimationFunction(lView, tNode, value));
  initializeAnimationQueueScheduler(lView[INJECTOR]);
  queueEnterAnimations(lView[INJECTOR], getLViewEnterAnimations(lView));
  return ɵɵanimateEnterListener;
}
function runEnterAnimationFunction(lView, tNode, value) {
  const nativeElement = getNativeByTNode(tNode, lView);
  ngDevMode && assertElementNodes(nativeElement, 'animate.enter');
  value.call(lView[CONTEXT], {
    target: nativeElement,
    animationComplete: noOpAnimationComplete
  });
}
function ɵɵanimateLeave(value) {
  performanceMarkFeature('NgAnimateLeave');
  if (typeof ngServerMode !== 'undefined' && ngServerMode || !areAnimationSupported) {
    return ɵɵanimateLeave;
  }
  ngDevMode && assertAnimationTypes(value, 'animate.leave');
  const lView = getLView();
  const animationsDisabled = areAnimationsDisabled(lView);
  if (animationsDisabled) {
    return ɵɵanimateLeave;
  }
  const tNode = getCurrentTNode();
  const ngZone = lView[INJECTOR].get(NgZone);
  enableAnimationRuntimeSupport();
  enableViewDetachAnimationsSupport();
  addAnimationToLView(getLViewLeaveAnimations(lView), tNode, () => runLeaveAnimations(lView, tNode, value, ngZone));
  initializeAnimationQueueScheduler(lView[INJECTOR]);
  return ɵɵanimateLeave;
}
function runLeaveAnimations(lView, tNode, value, ngZone) {
  const {
    promise,
    resolve
  } = promiseWithResolvers();
  const nativeElement = getNativeByTNode(tNode, lView);
  ngDevMode && assertElementNodes(nativeElement, 'animate.leave');
  const renderer = lView[RENDERER];
  allLeavingAnimations.add(lView[ID]);
  (getLViewLeaveAnimations(lView).get(tNode.index).resolvers ??= []).push(resolve);
  const activeClasses = getClassListFromValue(value);
  if (activeClasses && activeClasses.length > 0) {
    animateLeaveClassRunner(nativeElement, tNode, lView, activeClasses, renderer, ngZone);
  } else {
    resolve();
  }
  return {
    promise,
    resolve
  };
}
function animateLeaveClassRunner(el, tNode, lView, classList, renderer, ngZone) {
  cancelAnimationsIfRunning(el, renderer);
  const cleanupFns = [];
  const componentResolvers = getLViewLeaveAnimations(lView).get(tNode.index)?.resolvers;
  let fallbackTimeoutId;
  let hasCompleted = false;
  const handleOutAnimationEnd = event => {
    const target = getEventTarget(event);
    if (target !== el && event.type !== 'animation-fallback') return;
    if (event.type === 'animation-fallback' || event.detail?.cancel || isLongestAnimation(event, el)) {
      hasCompleted = true;
      if (fallbackTimeoutId) clearTimeout(fallbackTimeoutId);
      if (event.type !== 'animation-fallback') event.stopPropagation();
      longestAnimations.delete(el);
      clearLeavingNodes(tNode, el);
      removeClasses(renderer, el, classList);
      cleanupAfterLeaveAnimations(componentResolvers, cleanupFns);
      clearLViewNodeAnimationResolvers(lView, tNode);
    }
  };
  ngZone.runOutsideAngular(() => {
    cleanupFns.push(renderer.listen(el, 'animationend', handleOutAnimationEnd));
    cleanupFns.push(renderer.listen(el, 'transitionend', handleOutAnimationEnd));
  });
  trackLeavingNodes(tNode, el);
  addClasses(renderer, el, classList);
  ngZone.runOutsideAngular(() => {
    requestAnimationFrame(() => {
      if (hasCompleted) return;
      determineLongestAnimation(el, longestAnimations, areAnimationSupported);
      const longest = longestAnimations.get(el);
      if (!longest) {
        clearLeavingNodes(tNode, el);
        removeClasses(renderer, el, classList);
        cleanupAfterLeaveAnimations(componentResolvers, cleanupFns);
        clearLViewNodeAnimationResolvers(lView, tNode);
      } else {
        fallbackTimeoutId = setTimeout(() => {
          handleOutAnimationEnd(new CustomEvent('animation-fallback'));
        }, longest.duration + 50);
        cleanupFns.push(() => clearTimeout(fallbackTimeoutId));
      }
    });
  });
}
function ɵɵanimateLeaveListener(value) {
  performanceMarkFeature('NgAnimateLeave');
  if (typeof ngServerMode !== 'undefined' && ngServerMode || !areAnimationSupported) {
    return ɵɵanimateLeaveListener;
  }
  ngDevMode && assertAnimationTypes(value, 'animate.leave');
  const lView = getLView();
  const tNode = getCurrentTNode();
  allLeavingAnimations.add(lView[ID]);
  const ngZone = lView[INJECTOR].get(NgZone);
  const maxAnimationTimeout = lView[INJECTOR].get(MAX_ANIMATION_TIMEOUT);
  enableAnimationRuntimeSupport();
  enableViewDetachAnimationsSupport();
  addAnimationToLView(getLViewLeaveAnimations(lView), tNode, () => runLeaveAnimationFunction(lView, tNode, value, ngZone, maxAnimationTimeout));
  initializeAnimationQueueScheduler(lView[INJECTOR]);
  return ɵɵanimateLeaveListener;
}
function runLeaveAnimationFunction(lView, tNode, value, ngZone, maxAnimationTimeout) {
  const {
    promise,
    resolve
  } = promiseWithResolvers();
  const nativeElement = getNativeByTNode(tNode, lView);
  ngDevMode && assertElementNodes(nativeElement, 'animate.leave');
  const cleanupFns = [];
  const renderer = lView[RENDERER];
  const animationsDisabled = areAnimationsDisabled(lView);
  (getLViewLeaveAnimations(lView).get(tNode.index).resolvers ??= []).push(resolve);
  const resolvers = getLViewLeaveAnimations(lView).get(tNode.index)?.resolvers;
  if (animationsDisabled) {
    leaveAnimationFunctionCleanup(lView, tNode, nativeElement, resolvers, cleanupFns);
  } else {
    const timeoutId = setTimeout(() => leaveAnimationFunctionCleanup(lView, tNode, nativeElement, resolvers, cleanupFns), maxAnimationTimeout);
    const event = {
      target: nativeElement,
      animationComplete: () => {
        leaveAnimationFunctionCleanup(lView, tNode, nativeElement, resolvers, cleanupFns);
        clearTimeout(timeoutId);
      }
    };
    trackLeavingNodes(tNode, nativeElement);
    ngZone.runOutsideAngular(() => {
      cleanupFns.push(renderer.listen(nativeElement, 'animationend', () => {
        leaveAnimationFunctionCleanup(lView, tNode, nativeElement, resolvers, cleanupFns);
        clearTimeout(timeoutId);
      }, {
        once: true
      }));
    });
    value.call(lView[CONTEXT], event);
  }
  return {
    promise,
    resolve
  };
}

function ɵɵcomponentInstance() {
  const instance = getLView()[DECLARATION_COMPONENT_VIEW][CONTEXT];
  ngDevMode && assertDefined(instance, 'Expected component instance to be defined');
  return instance;
}

class LiveCollection {
  destroy(item) {}
  updateValue(index, value) {}
  swap(index1, index2) {
    const startIdx = Math.min(index1, index2);
    const endIdx = Math.max(index1, index2);
    const endItem = this.detach(endIdx);
    if (endIdx - startIdx > 1) {
      const startItem = this.detach(startIdx);
      this.attach(startIdx, endItem);
      this.attach(endIdx, startItem);
    } else {
      this.attach(startIdx, endItem);
    }
  }
  move(prevIndex, newIdx) {
    this.attach(newIdx, this.detach(prevIndex));
  }
}
function valuesMatching(liveIdx, liveValue, newIdx, newValue, trackBy) {
  if (liveIdx === newIdx && Object.is(liveValue, newValue)) {
    return 1;
  } else if (Object.is(trackBy(liveIdx, liveValue), trackBy(newIdx, newValue))) {
    return -1;
  }
  return 0;
}
function recordDuplicateKeys(keyToIdx, key, idx) {
  const idxSoFar = keyToIdx.get(key);
  if (idxSoFar !== undefined) {
    idxSoFar.add(idx);
  } else {
    keyToIdx.set(key, new Set([idx]));
  }
}
function reconcile(liveCollection, newCollection, trackByFn, reactiveConsumer) {
  let detachedItems = undefined;
  let liveKeysInTheFuture = undefined;
  let liveStartIdx = 0;
  let liveEndIdx = liveCollection.length - 1;
  const duplicateKeys = ngDevMode ? new Map() : undefined;
  if (Array.isArray(newCollection)) {
    setActiveConsumer$1(reactiveConsumer);
    let newEndIdx = newCollection.length - 1;
    setActiveConsumer$1(null);
    while (liveStartIdx <= liveEndIdx && liveStartIdx <= newEndIdx) {
      const liveStartValue = liveCollection.at(liveStartIdx);
      const newStartValue = newCollection[liveStartIdx];
      if (ngDevMode) {
        recordDuplicateKeys(duplicateKeys, trackByFn(liveStartIdx, newStartValue), liveStartIdx);
      }
      const isStartMatching = valuesMatching(liveStartIdx, liveStartValue, liveStartIdx, newStartValue, trackByFn);
      if (isStartMatching !== 0) {
        if (isStartMatching < 0) {
          liveCollection.updateValue(liveStartIdx, newStartValue);
        }
        liveStartIdx++;
        continue;
      }
      const liveEndValue = liveCollection.at(liveEndIdx);
      const newEndValue = newCollection[newEndIdx];
      if (ngDevMode) {
        recordDuplicateKeys(duplicateKeys, trackByFn(newEndIdx, newEndValue), newEndIdx);
      }
      const isEndMatching = valuesMatching(liveEndIdx, liveEndValue, newEndIdx, newEndValue, trackByFn);
      if (isEndMatching !== 0) {
        if (isEndMatching < 0) {
          liveCollection.updateValue(liveEndIdx, newEndValue);
        }
        liveEndIdx--;
        newEndIdx--;
        continue;
      }
      const liveStartKey = trackByFn(liveStartIdx, liveStartValue);
      const liveEndKey = trackByFn(liveEndIdx, liveEndValue);
      const newStartKey = trackByFn(liveStartIdx, newStartValue);
      if (Object.is(newStartKey, liveEndKey)) {
        const newEndKey = trackByFn(newEndIdx, newEndValue);
        if (Object.is(newEndKey, liveStartKey)) {
          liveCollection.swap(liveStartIdx, liveEndIdx);
          liveCollection.updateValue(liveEndIdx, newEndValue);
          newEndIdx--;
          liveEndIdx--;
        } else {
          liveCollection.move(liveEndIdx, liveStartIdx);
        }
        liveCollection.updateValue(liveStartIdx, newStartValue);
        liveStartIdx++;
        continue;
      }
      detachedItems ??= new UniqueValueMultiKeyMap();
      liveKeysInTheFuture ??= initLiveItemsInTheFuture(liveCollection, liveStartIdx, liveEndIdx, trackByFn);
      if (attachPreviouslyDetached(liveCollection, detachedItems, liveStartIdx, newStartKey)) {
        liveCollection.updateValue(liveStartIdx, newStartValue);
        liveStartIdx++;
        liveEndIdx++;
      } else if (!liveKeysInTheFuture.has(newStartKey)) {
        const newItem = liveCollection.create(liveStartIdx, newCollection[liveStartIdx]);
        liveCollection.attach(liveStartIdx, newItem);
        liveStartIdx++;
        liveEndIdx++;
      } else {
        detachedItems.set(liveStartKey, liveCollection.detach(liveStartIdx));
        liveEndIdx--;
      }
    }
    while (liveStartIdx <= newEndIdx) {
      createOrAttach(liveCollection, detachedItems, trackByFn, liveStartIdx, newCollection[liveStartIdx]);
      liveStartIdx++;
    }
  } else if (newCollection != null) {
    setActiveConsumer$1(reactiveConsumer);
    const newCollectionIterator = newCollection[Symbol.iterator]();
    setActiveConsumer$1(null);
    let newIterationResult = newCollectionIterator.next();
    while (!newIterationResult.done && liveStartIdx <= liveEndIdx) {
      const liveValue = liveCollection.at(liveStartIdx);
      const newValue = newIterationResult.value;
      if (ngDevMode) {
        recordDuplicateKeys(duplicateKeys, trackByFn(liveStartIdx, newValue), liveStartIdx);
      }
      const isStartMatching = valuesMatching(liveStartIdx, liveValue, liveStartIdx, newValue, trackByFn);
      if (isStartMatching !== 0) {
        if (isStartMatching < 0) {
          liveCollection.updateValue(liveStartIdx, newValue);
        }
        liveStartIdx++;
        newIterationResult = newCollectionIterator.next();
      } else {
        detachedItems ??= new UniqueValueMultiKeyMap();
        liveKeysInTheFuture ??= initLiveItemsInTheFuture(liveCollection, liveStartIdx, liveEndIdx, trackByFn);
        const newKey = trackByFn(liveStartIdx, newValue);
        if (attachPreviouslyDetached(liveCollection, detachedItems, liveStartIdx, newKey)) {
          liveCollection.updateValue(liveStartIdx, newValue);
          liveStartIdx++;
          liveEndIdx++;
          newIterationResult = newCollectionIterator.next();
        } else if (!liveKeysInTheFuture.has(newKey)) {
          liveCollection.attach(liveStartIdx, liveCollection.create(liveStartIdx, newValue));
          liveStartIdx++;
          liveEndIdx++;
          newIterationResult = newCollectionIterator.next();
        } else {
          const liveKey = trackByFn(liveStartIdx, liveValue);
          detachedItems.set(liveKey, liveCollection.detach(liveStartIdx));
          liveEndIdx--;
        }
      }
    }
    while (!newIterationResult.done) {
      createOrAttach(liveCollection, detachedItems, trackByFn, liveCollection.length, newIterationResult.value);
      newIterationResult = newCollectionIterator.next();
    }
  }
  while (liveStartIdx <= liveEndIdx) {
    liveCollection.destroy(liveCollection.detach(liveEndIdx--));
  }
  detachedItems?.forEach(item => {
    liveCollection.destroy(item);
  });
  if (ngDevMode) {
    let duplicatedKeysMsg = [];
    for (const [key, idxSet] of duplicateKeys) {
      if (idxSet.size > 1) {
        const idx = [...idxSet].sort((a, b) => a - b);
        for (let i = 1; i < idx.length; i++) {
          duplicatedKeysMsg.push(`key "${stringifyForError(key)}" at index "${idx[i - 1]}" and "${idx[i]}"`);
        }
      }
    }
    if (duplicatedKeysMsg.length > 0) {
      const message = formatRuntimeError(-955, 'The provided track expression resulted in duplicated keys for a given collection. ' + 'Adjust the tracking expression such that it uniquely identifies all the items in the collection. ' + 'Duplicated keys were: \n' + duplicatedKeysMsg.join(', \n') + '.');
      console.warn(message);
    }
  }
}
function attachPreviouslyDetached(prevCollection, detachedItems, index, key) {
  if (detachedItems !== undefined && detachedItems.has(key)) {
    prevCollection.attach(index, detachedItems.get(key));
    detachedItems.delete(key);
    return true;
  }
  return false;
}
function createOrAttach(liveCollection, detachedItems, trackByFn, index, value) {
  if (!attachPreviouslyDetached(liveCollection, detachedItems, index, trackByFn(index, value))) {
    const newItem = liveCollection.create(index, value);
    liveCollection.attach(index, newItem);
  } else {
    liveCollection.updateValue(index, value);
  }
}
function initLiveItemsInTheFuture(liveCollection, start, end, trackByFn) {
  const keys = new Set();
  for (let i = start; i <= end; i++) {
    keys.add(trackByFn(i, liveCollection.at(i)));
  }
  return keys;
}
class UniqueValueMultiKeyMap {
  kvMap = new Map();
  _vMap = undefined;
  has(key) {
    return this.kvMap.has(key);
  }
  delete(key) {
    if (!this.has(key)) return false;
    const value = this.kvMap.get(key);
    if (this._vMap !== undefined && this._vMap.has(value)) {
      this.kvMap.set(key, this._vMap.get(value));
      this._vMap.delete(value);
    } else {
      this.kvMap.delete(key);
    }
    return true;
  }
  get(key) {
    return this.kvMap.get(key);
  }
  set(key, value) {
    if (this.kvMap.has(key)) {
      let prevValue = this.kvMap.get(key);
      if (ngDevMode && prevValue === value) {
        throw new Error(`Detected a duplicated value ${value} for the key ${key}`);
      }
      if (this._vMap === undefined) {
        this._vMap = new Map();
      }
      const vMap = this._vMap;
      while (vMap.has(prevValue)) {
        prevValue = vMap.get(prevValue);
      }
      vMap.set(prevValue, value);
    } else {
      this.kvMap.set(key, value);
    }
  }
  forEach(cb) {
    for (let [key, value] of this.kvMap) {
      cb(value, key);
      if (this._vMap !== undefined) {
        const vMap = this._vMap;
        while (vMap.has(value)) {
          value = vMap.get(value);
          cb(value, key);
        }
      }
    }
  }
}

function ɵɵconditionalCreate(index, templateFn, decls, vars, tagName, attrsIndex, localRefsIndex, localRefExtractor) {
  performanceMarkFeature('NgControlFlow');
  const lView = getLView();
  const tView = getTView();
  const attrs = getConstant(tView.consts, attrsIndex);
  declareNoDirectiveHostTemplate(lView, tView, index, templateFn, decls, vars, tagName, attrs, 256, localRefsIndex, localRefExtractor);
  return ɵɵconditionalBranchCreate;
}
function ɵɵconditionalBranchCreate(index, templateFn, decls, vars, tagName, attrsIndex, localRefsIndex, localRefExtractor) {
  performanceMarkFeature('NgControlFlow');
  createControlFlowBranch(index, templateFn, decls, vars, tagName, attrsIndex, localRefsIndex, localRefExtractor);
  return ɵɵconditionalBranchCreate;
}
function createControlFlowBranch(index, templateFn, decls, vars, tagName, attrsIndex, localRefsIndex, localRefExtractor) {
  const lView = getLView();
  const tView = getTView();
  const attrs = getConstant(tView.consts, attrsIndex);
  declareNoDirectiveHostTemplate(lView, tView, index, templateFn, decls, vars, tagName, attrs, 512, localRefsIndex, localRefExtractor);
}
function ɵɵconditional(matchingTemplateIndex, contextValue) {
  performanceMarkFeature('NgControlFlow');
  const hostLView = getLView();
  const bindingIndex = nextBindingIndex();
  const prevMatchingTemplateIndex = hostLView[bindingIndex] !== NO_CHANGE ? hostLView[bindingIndex] : -1;
  const prevContainer = prevMatchingTemplateIndex !== -1 ? getLContainer(hostLView, HEADER_OFFSET + prevMatchingTemplateIndex) : undefined;
  const viewInContainerIdx = 0;
  if (bindingUpdated(hostLView, bindingIndex, matchingTemplateIndex)) {
    const prevConsumer = setActiveConsumer(null);
    try {
      if (prevContainer !== undefined) {
        removeLViewFromLContainer(prevContainer, viewInContainerIdx);
      }
      if (matchingTemplateIndex !== -1) {
        const nextLContainerIndex = HEADER_OFFSET + matchingTemplateIndex;
        const nextContainer = getLContainer(hostLView, nextLContainerIndex);
        const templateTNode = getExistingTNode(hostLView[TVIEW$1], nextLContainerIndex);
        const dehydratedView = findAndReconcileMatchingDehydratedViews(nextContainer, templateTNode, hostLView);
        const embeddedLView = createAndRenderEmbeddedLView(hostLView, templateTNode, contextValue, {
          dehydratedView
        });
        addLViewToLContainer(nextContainer, embeddedLView, viewInContainerIdx, shouldAddViewToDom(templateTNode, dehydratedView));
      }
    } finally {
      setActiveConsumer(prevConsumer);
    }
  } else if (prevContainer !== undefined) {
    const lView = getLViewFromLContainer(prevContainer, viewInContainerIdx);
    if (lView !== undefined) {
      lView[CONTEXT] = contextValue;
    }
  }
}
class RepeaterContext {
  lContainer;
  $implicit;
  $index;
  constructor(lContainer, $implicit, $index) {
    this.lContainer = lContainer;
    this.$implicit = $implicit;
    this.$index = $index;
  }
  get $count() {
    return this.lContainer.length - CONTAINER_HEADER_OFFSET;
  }
}
function ɵɵrepeaterTrackByIndex(index) {
  return index;
}
function ɵɵrepeaterTrackByIdentity(_, value) {
  return value;
}
class RepeaterMetadata {
  hasEmptyBlock;
  trackByFn;
  liveCollection;
  constructor(hasEmptyBlock, trackByFn, liveCollection) {
    this.hasEmptyBlock = hasEmptyBlock;
    this.trackByFn = trackByFn;
    this.liveCollection = liveCollection;
  }
}
function ɵɵrepeaterCreate(index, templateFn, decls, vars, tagName, attrsIndex, trackByFn, trackByUsesComponentInstance, emptyTemplateFn, emptyDecls, emptyVars, emptyTagName, emptyAttrsIndex) {
  performanceMarkFeature('NgControlFlow');
  ngDevMode && assertFunction(trackByFn, `A track expression must be a function, was ${typeof trackByFn} instead.`);
  const lView = getLView();
  const tView = getTView();
  const hasEmptyBlock = emptyTemplateFn !== undefined;
  const hostLView = getLView();
  const boundTrackBy = trackByUsesComponentInstance ? trackByFn.bind(hostLView[DECLARATION_COMPONENT_VIEW][CONTEXT]) : trackByFn;
  const metadata = new RepeaterMetadata(hasEmptyBlock, boundTrackBy);
  hostLView[HEADER_OFFSET + index] = metadata;
  declareNoDirectiveHostTemplate(lView, tView, index + 1, templateFn, decls, vars, tagName, getConstant(tView.consts, attrsIndex), 256);
  if (hasEmptyBlock) {
    ngDevMode && assertDefined(emptyDecls, 'Missing number of declarations for the empty repeater block.');
    ngDevMode && assertDefined(emptyVars, 'Missing number of bindings for the empty repeater block.');
    declareNoDirectiveHostTemplate(lView, tView, index + 2, emptyTemplateFn, emptyDecls, emptyVars, emptyTagName, getConstant(tView.consts, emptyAttrsIndex), 512);
  }
}
function isViewExpensiveToRecreate(lView) {
  return lView.length - HEADER_OFFSET > 2;
}
class OperationsCounter {
  created = 0;
  destroyed = 0;
  reset() {
    this.created = 0;
    this.destroyed = 0;
  }
  recordCreate() {
    this.created++;
  }
  recordDestroy() {
    this.destroyed++;
  }
  wasReCreated(collectionLen) {
    return collectionLen > 0 && this.created === this.destroyed && this.created === collectionLen;
  }
}
class LiveCollectionLContainerImpl extends LiveCollection {
  lContainer;
  hostLView;
  templateTNode;
  operationsCounter = ngDevMode ? new OperationsCounter() : undefined;
  needsIndexUpdate = false;
  constructor(lContainer, hostLView, templateTNode) {
    super();
    this.lContainer = lContainer;
    this.hostLView = hostLView;
    this.templateTNode = templateTNode;
  }
  get length() {
    return this.lContainer.length - CONTAINER_HEADER_OFFSET;
  }
  at(index) {
    return this.getLView(index)[CONTEXT].$implicit;
  }
  attach(index, lView) {
    const dehydratedView = lView[HYDRATION];
    this.needsIndexUpdate ||= index !== this.length;
    addLViewToLContainer(this.lContainer, lView, index, shouldAddViewToDom(this.templateTNode, dehydratedView));
    clearDetachAnimationList(this.lContainer, index);
  }
  detach(index) {
    this.needsIndexUpdate ||= index !== this.length - 1;
    maybeInitDetachAnimationList(this.lContainer, index);
    return detachExistingView(this.lContainer, index);
  }
  create(index, value) {
    const dehydratedView = findMatchingDehydratedView(this.lContainer, this.templateTNode.tView.ssrId);
    const embeddedLView = createAndRenderEmbeddedLView(this.hostLView, this.templateTNode, new RepeaterContext(this.lContainer, value, index), {
      dehydratedView
    });
    ngDevMode && this.operationsCounter?.recordCreate();
    return embeddedLView;
  }
  destroy(lView) {
    destroyLView(lView[TVIEW$1], lView);
    ngDevMode && this.operationsCounter?.recordDestroy();
  }
  updateValue(index, value) {
    this.getLView(index)[CONTEXT].$implicit = value;
  }
  reset() {
    this.needsIndexUpdate = false;
    ngDevMode && this.operationsCounter?.reset();
  }
  updateIndexes() {
    if (this.needsIndexUpdate) {
      for (let i = 0; i < this.length; i++) {
        this.getLView(i)[CONTEXT].$index = i;
      }
    }
  }
  getLView(index) {
    return getExistingLViewFromLContainer(this.lContainer, index);
  }
}
function ɵɵrepeater(collection) {
  const prevConsumer = setActiveConsumer(null);
  const metadataSlotIdx = getSelectedIndex();
  try {
    const hostLView = getLView();
    const hostTView = hostLView[TVIEW$1];
    const metadata = hostLView[metadataSlotIdx];
    const containerIndex = metadataSlotIdx + 1;
    const lContainer = getLContainer(hostLView, containerIndex);
    if (metadata.liveCollection === undefined) {
      const itemTemplateTNode = getExistingTNode(hostTView, containerIndex);
      metadata.liveCollection = new LiveCollectionLContainerImpl(lContainer, hostLView, itemTemplateTNode);
    } else {
      metadata.liveCollection.reset();
    }
    const liveCollection = metadata.liveCollection;
    reconcile(liveCollection, collection, metadata.trackByFn, prevConsumer);
    if (ngDevMode && metadata.trackByFn === ɵɵrepeaterTrackByIdentity && liveCollection.operationsCounter?.wasReCreated(liveCollection.length) && isViewExpensiveToRecreate(getExistingLViewFromLContainer(lContainer, 0))) {
      const message = formatRuntimeError(-956, `The configured tracking expression (track by identity) caused re-creation of the entire collection of size ${liveCollection.length}. ` + 'This is an expensive operation requiring destruction and subsequent creation of DOM nodes, directives, components etc. ' + 'Please review the "track expression" and make sure that it uniquely identifies items in a collection.');
      console.warn(message);
    }
    liveCollection.updateIndexes();
    if (metadata.hasEmptyBlock) {
      const bindingIndex = nextBindingIndex();
      const isCollectionEmpty = liveCollection.length === 0;
      if (bindingUpdated(hostLView, bindingIndex, isCollectionEmpty)) {
        const emptyTemplateIndex = metadataSlotIdx + 2;
        const lContainerForEmpty = getLContainer(hostLView, emptyTemplateIndex);
        if (isCollectionEmpty) {
          const emptyTemplateTNode = getExistingTNode(hostTView, emptyTemplateIndex);
          const dehydratedView = findAndReconcileMatchingDehydratedViews(lContainerForEmpty, emptyTemplateTNode, hostLView);
          const embeddedLView = createAndRenderEmbeddedLView(hostLView, emptyTemplateTNode, undefined, {
            dehydratedView
          });
          addLViewToLContainer(lContainerForEmpty, embeddedLView, 0, shouldAddViewToDom(emptyTemplateTNode, dehydratedView));
        } else {
          if (hostTView.firstUpdatePass) {
            removeDehydratedViews(lContainerForEmpty);
          }
          removeLViewFromLContainer(lContainerForEmpty, 0);
        }
      }
    }
  } finally {
    setActiveConsumer(prevConsumer);
  }
}
function getLContainer(lView, index) {
  const lContainer = lView[index];
  ngDevMode && assertLContainer(lContainer);
  return lContainer;
}
function clearDetachAnimationList(lContainer, index) {
  if (lContainer.length <= CONTAINER_HEADER_OFFSET) return;
  const indexInContainer = CONTAINER_HEADER_OFFSET + index;
  const viewToDetach = lContainer[indexInContainer];
  if (viewToDetach) {
    clearViewDetachAnimations(viewToDetach);
  }
}
function maybeInitDetachAnimationList(lContainer, index) {
  if (lContainer.length <= CONTAINER_HEADER_OFFSET) return;
  const indexInContainer = CONTAINER_HEADER_OFFSET + index;
  const viewToDetach = lContainer[indexInContainer];
  if (viewToDetach) {
    initViewDetachAnimations(viewToDetach);
  }
}
function detachExistingView(lContainer, index) {
  const existingLView = detachView(lContainer, index);
  ngDevMode && assertLView(existingLView);
  return existingLView;
}
function getExistingLViewFromLContainer(lContainer, index) {
  const existingLView = getLViewFromLContainer(lContainer, index);
  ngDevMode && assertLView(existingLView);
  return existingLView;
}
function getExistingTNode(tView, index) {
  const tNode = getTNode(tView, index);
  ngDevMode && assertTNode(tNode);
  return tNode;
}

class BoundaryError extends Error {
  constructor(message, options) {
    super(message, options);
    this.name = 'BoundaryError';
  }
}
class LBoundary {
  hostLView;
  error = null;
  constructor(hostLView) {
    this.hostLView = hostLView;
  }
  reset() {
    this.error = null;
    markViewForRefresh(this.hostLView);
  }
}
function ɵɵboundaryCreate(index) {
  performanceMarkFeature('NgBoundary');
  const lView = getLView();
  lView[HEADER_OFFSET + index] = new LBoundary(lView);
}
function ɵɵgetBoundary(index) {
  const lView = getLView();
  return lView[HEADER_OFFSET + index];
}
function ɵɵboundaryUpdate(slotIndex, matchingTemplateIndex, primaryTemplateIndex) {
  const hostLView = getLView();
  const bindingIndex = nextBindingIndex();
  const prevMatchingTemplateIndex = hostLView[bindingIndex] !== NO_CHANGE ? hostLView[bindingIndex] : -1;
  const prevContainer = prevMatchingTemplateIndex !== -1 ? getLContainer(hostLView, HEADER_OFFSET + prevMatchingTemplateIndex) : undefined;
  const viewInContainerIdx = 0;
  if (bindingUpdated(hostLView, bindingIndex, matchingTemplateIndex)) {
    const prevConsumer = setActiveConsumer(null);
    try {
      if (prevContainer !== undefined) {
        removeLViewFromLContainer(prevContainer, viewInContainerIdx);
      }
      if (matchingTemplateIndex !== -1) {
        const nextLContainerIndex = HEADER_OFFSET + matchingTemplateIndex;
        const nextContainer = getLContainer(hostLView, nextLContainerIndex);
        const templateTNode = getExistingTNode(hostLView[TVIEW$1], nextLContainerIndex);
        const dehydratedView = findAndReconcileMatchingDehydratedViews(nextContainer, templateTNode, hostLView);
        let embeddedLView;
        try {
          const boundary = hostLView[HEADER_OFFSET + slotIndex];
          const context = matchingTemplateIndex === primaryTemplateIndex ? undefined : {
            $error: boundary.error,
            $reset: () => boundary.reset()
          };
          embeddedLView = createAndRenderEmbeddedLView(hostLView, templateTNode, context, {
            dehydratedView
          });
          if (matchingTemplateIndex === primaryTemplateIndex) {
            embeddedLView[ON_ERROR] = (error, details) => {
              const boundary = hostLView[HEADER_OFFSET + slotIndex];
              boundary.error = error;
              const errorHandler = hostLView[INJECTOR]?.get(ErrorHandler, null);
              if (errorHandler) {
                const boundaryComponentView = hostLView[DECLARATION_COMPONENT_VIEW][CONTEXT];
                const boundaryType = boundaryComponentView.constructor;
                details.boundary = {
                  type: boundaryType,
                  reset: () => boundary.reset()
                };
                if (errorHandler.onViewError) {
                  errorHandler.onViewError(error, details);
                } else {
                  errorHandler.handleError(error);
                }
              }
              removeLViewFromLContainer(nextContainer, viewInContainerIdx);
              markViewForRefresh(hostLView);
            };
          }
        } catch (e) {
          if (matchingTemplateIndex === primaryTemplateIndex) {
            const boundary = hostLView[HEADER_OFFSET + slotIndex];
            boundary.error = e;
            const errorHandler = hostLView[INJECTOR]?.get(ErrorHandler, null);
            if (errorHandler) {
              const boundaryError = encapsulateBoundaryError(e);
              const declarationInstance = hostLView[DECLARATION_COMPONENT_VIEW][CONTEXT];
              const declarationType = declarationInstance.constructor;
              const details = {
                declarationInstance,
                declarationType,
                boundary: {
                  type: declarationType,
                  reset: () => boundary.reset()
                }
              };
              if (errorHandler.onViewError) {
                errorHandler.onViewError(boundaryError, details);
              } else {
                errorHandler.handleError(boundaryError);
              }
            }
            markViewForRefresh(hostLView);
            return;
          }
          throw e;
        }
        addLViewToLContainer(nextContainer, embeddedLView, viewInContainerIdx, shouldAddViewToDom(templateTNode, dehydratedView));
      } else {
        const boundary = hostLView[HEADER_OFFSET + slotIndex];
        throw new BoundaryError('Unhandled error in @boundary fell through.', {
          cause: boundary.error
        });
      }
    } finally {
      setActiveConsumer(prevConsumer);
    }
  }
}

function ɵɵproperty(propName, value, sanitizer) {
  const lView = getLView();
  const bindingIndex = nextBindingIndex();
  if (bindingUpdated(lView, bindingIndex, value)) {
    const tView = getTView();
    const tNode = getSelectedTNode();
    setPropertyAndInputs(tNode, lView, propName, value, lView[RENDERER], sanitizer);
    ngDevMode && storePropertyBindingMetadata(tView.data, tNode, propName, bindingIndex);
  }
  return ɵɵproperty;
}
function setDirectiveInputsWhichShadowsStyling(tView, tNode, lView, value, isClassBased) {
  setAllInputsForProperty(tNode, tView, lView, isClassBased ? 'class' : 'style', value);
}

function ɵɵelementStart(index, name, attrsIndex, localRefsIndex) {
  const lView = getLView();
  ngDevMode && assertTNodeCreationIndex(lView, index);
  const tView = lView[TVIEW$1];
  const adjustedIndex = index + HEADER_OFFSET;
  const tNode = tView.firstCreatePass ? directiveHostFirstCreatePass(adjustedIndex, lView, 2, name, findDirectiveDefMatches, getBindingsEnabled(), attrsIndex, localRefsIndex) : tView.data[adjustedIndex];
  if (isComponentHost(tNode)) {
    const tracingService = lView[ENVIRONMENT].tracingService;
    if (tracingService && tracingService.componentCreate) {
      const def = tView.data[tNode.directiveStart + tNode.componentOffset];
      return tracingService.componentCreate(getComponentName(def), () => {
        initializeElement(index, name, lView, tNode, localRefsIndex);
        return ɵɵelementStart;
      });
    }
  }
  initializeElement(index, name, lView, tNode, localRefsIndex);
  return ɵɵelementStart;
}
function initializeElement(index, name, lView, tNode, localRefsIndex) {
  elementLikeStartShared(tNode, lView, index, name, _locateOrCreateElementNode);
  if (isDirectiveHost(tNode)) {
    const tView = lView[TVIEW$1];
    createDirectivesInstances(tView, lView, tNode);
    executeContentQueries(tView, tNode, lView);
  }
  if (localRefsIndex != null) {
    saveResolvedLocalsInData(lView, tNode);
  }
  if (ngDevMode && lView[TVIEW$1].firstCreatePass) {
    validateElementIsKnown(lView, tNode);
  }
}
function ɵɵelementEnd() {
  const tView = getTView();
  const initialTNode = getCurrentTNode();
  ngDevMode && assertDefined(initialTNode, 'No parent node to close.');
  const currentTNode = elementLikeEndShared(initialTNode);
  ngDevMode && assertTNodeType(currentTNode, 3);
  if (tView.firstCreatePass) {
    directiveHostEndFirstCreatePass(tView, currentTNode);
  }
  if (isSkipHydrationRootTNode(currentTNode)) {
    leaveSkipHydrationBlock();
  }
  decreaseElementDepthCount();
  if (currentTNode.classesWithoutHost != null && hasClassInput(currentTNode)) {
    setDirectiveInputsWhichShadowsStyling(tView, currentTNode, getLView(), currentTNode.classesWithoutHost, true);
  }
  if (currentTNode.stylesWithoutHost != null && hasStyleInput(currentTNode)) {
    setDirectiveInputsWhichShadowsStyling(tView, currentTNode, getLView(), currentTNode.stylesWithoutHost, false);
  }
  return ɵɵelementEnd;
}
function ɵɵelement(index, name, attrsIndex, localRefsIndex) {
  ɵɵelementStart(index, name, attrsIndex, localRefsIndex);
  ɵɵelementEnd();
  return ɵɵelement;
}
function ɵɵdomElementStart(index, name, attrsIndex, localRefsIndex) {
  const lView = getLView();
  ngDevMode && assertTNodeCreationIndex(lView, index);
  const tView = lView[TVIEW$1];
  const adjustedIndex = index + HEADER_OFFSET;
  const tNode = tView.firstCreatePass ? domOnlyFirstCreatePass(adjustedIndex, tView, 2, name, attrsIndex, localRefsIndex) : tView.data[adjustedIndex];
  elementLikeStartShared(tNode, lView, index, name, _locateOrCreateElementNode);
  if (localRefsIndex != null) {
    saveResolvedLocalsInData(lView, tNode);
  }
  if (ngDevMode && lView[TVIEW$1].firstCreatePass) {
    validateElementIsKnown(lView, tNode);
  }
  return ɵɵdomElementStart;
}
function ɵɵdomElementEnd() {
  const initialTNode = getCurrentTNode();
  ngDevMode && assertDefined(initialTNode, 'No parent node to close.');
  const currentTNode = elementLikeEndShared(initialTNode);
  ngDevMode && assertTNodeType(currentTNode, 3);
  if (isSkipHydrationRootTNode(currentTNode)) {
    leaveSkipHydrationBlock();
  }
  decreaseElementDepthCount();
  return ɵɵdomElementEnd;
}
function ɵɵdomElement(index, name, attrsIndex, localRefsIndex) {
  ɵɵdomElementStart(index, name, attrsIndex, localRefsIndex);
  ɵɵdomElementEnd();
  return ɵɵdomElement;
}
let _locateOrCreateElementNode = (tView, lView, tNode, name, index) => {
  lastNodeWasCreated(true);
  return createElementNode(lView[RENDERER], name, getNamespace());
};
function locateOrCreateElementNodeImpl(tView, lView, tNode, name, index) {
  const isNodeCreationMode = !canHydrateNode(lView, tNode);
  lastNodeWasCreated(isNodeCreationMode);
  if (isNodeCreationMode) {
    return createElementNode(lView[RENDERER], name, getNamespace());
  }
  const hydrationInfo = lView[HYDRATION];
  const native = locateNextRNode(hydrationInfo, tView, lView, tNode);
  ngDevMode && validateMatchingNode(native, Node.ELEMENT_NODE, name, lView, tNode);
  ngDevMode && markRNodeAsClaimedByHydration(native);
  if (getSerializedContainerViews(hydrationInfo, index)) {
    ngDevMode && validateNodeExists(native.nextSibling, lView, tNode);
    setSegmentHead(hydrationInfo, index, native.nextSibling);
  }
  if (hydrationInfo) {
    if (native == null) {
      throw new RuntimeError(-502, ngDevMode && (() => {
        const host = lView[HOST] ?? lView[DECLARATION_COMPONENT_VIEW]?.[HOST];
        return host ? `During hydration Angular expected a "<${name}>" element inside <${host.tagName.toLowerCase()}>, but no matching DOM node was found. This usually means the client-rendered DOM no longer matches the server-rendered HTML.` : `During hydration Angular expected a "<${name}>" element at this location, but no matching DOM node was found. This usually means the client-rendered DOM no longer matches the server-rendered HTML.`;
      })());
    }
    if (native.nodeType !== Node.ELEMENT_NODE) {
      throw new RuntimeError(-500, ngDevMode && `During hydration Angular expected an element at this location, but found a ${describeDomNode(native)} node instead.`);
    }
    if (hasSkipHydrationAttrOnTNode(tNode) || hasSkipHydrationAttrOnRElement(native)) {
      if (isComponentHost(tNode)) {
        enterSkipHydrationBlock(tNode);
        clearElementContents(native);
        ngDevMode && markRNodeAsSkippedByHydration(native);
      } else if (ngDevMode) {
        throw invalidSkipHydrationHost(native);
      }
    }
  }
  return native;
}
function enableLocateOrCreateElementNodeImpl() {
  _locateOrCreateElementNode = locateOrCreateElementNodeImpl;
}

function ɵɵelementContainerStart(index, attrsIndex, localRefsIndex) {
  const lView = getLView();
  ngDevMode && assertTNodeCreationIndex(lView, index);
  const tView = lView[TVIEW$1];
  const adjustedIndex = index + HEADER_OFFSET;
  const tNode = tView.firstCreatePass ? directiveHostFirstCreatePass(adjustedIndex, lView, 8, 'ng-container', findDirectiveDefMatches, getBindingsEnabled(), attrsIndex, localRefsIndex) : tView.data[adjustedIndex];
  elementLikeStartShared(tNode, lView, index, 'ng-container', _locateOrCreateElementContainerNode);
  if (isDirectiveHost(tNode)) {
    const tView = lView[TVIEW$1];
    createDirectivesInstances(tView, lView, tNode);
    executeContentQueries(tView, tNode, lView);
  }
  if (localRefsIndex != null) {
    saveResolvedLocalsInData(lView, tNode);
  }
  return ɵɵelementContainerStart;
}
function ɵɵelementContainerEnd() {
  const tView = getTView();
  const initialTNode = getCurrentTNode();
  ngDevMode && assertDefined(initialTNode, 'No parent node to close.');
  const currentTNode = elementLikeEndShared(initialTNode);
  if (tView.firstCreatePass) {
    directiveHostEndFirstCreatePass(tView, currentTNode);
  }
  ngDevMode && assertTNodeType(currentTNode, 8);
  return ɵɵelementContainerEnd;
}
function ɵɵelementContainer(index, attrsIndex, localRefsIndex) {
  ɵɵelementContainerStart(index, attrsIndex, localRefsIndex);
  ɵɵelementContainerEnd();
  return ɵɵelementContainer;
}
function ɵɵdomElementContainerStart(index, attrsIndex, localRefsIndex) {
  const lView = getLView();
  ngDevMode && assertTNodeCreationIndex(lView, index);
  const tView = lView[TVIEW$1];
  const adjustedIndex = index + HEADER_OFFSET;
  const tNode = tView.firstCreatePass ? domOnlyFirstCreatePass(adjustedIndex, tView, 8, 'ng-container', attrsIndex, localRefsIndex) : tView.data[adjustedIndex];
  elementLikeStartShared(tNode, lView, index, 'ng-container', _locateOrCreateElementContainerNode);
  if (localRefsIndex != null) {
    saveResolvedLocalsInData(lView, tNode);
  }
  return ɵɵdomElementContainerStart;
}
function ɵɵdomElementContainerEnd() {
  const initialTNode = getCurrentTNode();
  ngDevMode && assertDefined(initialTNode, 'No parent node to close.');
  const currentTNode = elementLikeEndShared(initialTNode);
  ngDevMode && assertTNodeType(currentTNode, 8);
  return ɵɵelementContainerEnd;
}
function ɵɵdomElementContainer(index, attrsIndex, localRefsIndex) {
  ɵɵdomElementContainerStart(index, attrsIndex, localRefsIndex);
  ɵɵdomElementContainerEnd();
  return ɵɵdomElementContainer;
}
let _locateOrCreateElementContainerNode = (tView, lView, tNode, commentText, index) => {
  lastNodeWasCreated(true);
  return createCommentNode(lView[RENDERER], ngDevMode ? commentText : '');
};
function locateOrCreateElementContainerNode(tView, lView, tNode, commentText, index) {
  let comment;
  const isNodeCreationMode = !canHydrateNode(lView, tNode);
  lastNodeWasCreated(isNodeCreationMode);
  if (isNodeCreationMode) {
    return createCommentNode(lView[RENDERER], ngDevMode ? commentText : '');
  }
  const hydrationInfo = lView[HYDRATION];
  const currentRNode = locateNextRNode(hydrationInfo, tView, lView, tNode);
  ngDevMode && validateNodeExists(currentRNode, lView, tNode);
  const ngContainerSize = getNgContainerSize(hydrationInfo, index);
  ngDevMode && assertNumber(ngContainerSize, 'Unexpected state: hydrating an <ng-container>, ' + 'but no hydration info is available.');
  setSegmentHead(hydrationInfo, index, currentRNode);
  comment = siblingAfter(ngContainerSize, currentRNode);
  if (ngDevMode) {
    validateMatchingNode(comment, Node.COMMENT_NODE, null, lView, tNode);
    markRNodeAsClaimedByHydration(comment);
  }
  return comment;
}
function enableLocateOrCreateElementContainerNodeImpl() {
  _locateOrCreateElementContainerNode = locateOrCreateElementContainerNode;
}

const FOREIGN_CONTEXT = new InjectionToken('FOREIGN_CONTEXT');

class ForeignViewRef extends ViewRef {
  get head() {
    const lView = this._lView;
    const tView = lView[TVIEW$1];
    return lView[tView.firstChild.index];
  }
  get tail() {
    const lView = this._lView;
    const tView = lView[TVIEW$1];
    return lView[tView.firstChild.next.index];
  }
}
function createForeignView(lContainer, index) {
  const declLView = lContainer[PARENT];
  const declTNode = lContainer[T_HOST];
  const renderer = declLView[RENDERER];
  const tView = createTView(3, declTNode, null, 3, 0, null, null, null, null, null, null);
  const headTNode = tView.data[HEADER_OFFSET] = createTNode(tView, null, 2, HEADER_OFFSET, '', null);
  const tailTNode = tView.data[HEADER_OFFSET + 1] = createTNode(tView, null, 2, HEADER_OFFSET + 1, '', null);
  tView.firstChild = headTNode;
  headTNode.next = tailTNode;
  tailTNode.prev = headTNode;
  const lView = createLView(declLView, tView, null, 0, null, null, null, renderer, null, null, null);
  const headComment = lView[headTNode.index] = renderer.createComment(ngDevMode ? 'foreign-view-head' : '');
  const tailComment = lView[tailTNode.index] = renderer.createComment(ngDevMode ? 'foreign-view-tail' : '');
  lView[FLAGS] &= -5;
  const viewRef = new ForeignViewRef(lView);
  addLViewToLContainer(lContainer, lView, index);
  if (!headComment.parentNode) {
    const fragment = document.createDocumentFragment();
    fragment.appendChild(headComment);
    fragment.appendChild(tailComment);
    const fragmentSlotIndex = tailTNode.index + 1;
    lView[fragmentSlotIndex] = fragment;
  }
  return viewRef;
}

function ɵɵforeignComponent(index, foreignComponentIndex, props) {
  const lView = getLView();
  const tView = getTView();
  const adjustedIndex = index + HEADER_OFFSET;
  const foreignComponent = getConstant(tView.consts, foreignComponentIndex);
  let tNode;
  if (tView.firstCreatePass) {
    tNode = getOrCreateTNode(tView, adjustedIndex, 4, null, null);
    setCurrentTNodeAsNotParent();
  } else {
    tNode = tView.data[adjustedIndex];
    setCurrentTNode(tNode, false);
  }
  const renderer = lView[RENDERER];
  const comment = renderer.createComment(ngDevMode ? 'foreign-component' : '');
  appendChild(tView, lView, comment, tNode);
  attachPatchData(comment, lView);
  const lContainer = createLContainer(comment, lView, comment, tNode);
  lView[adjustedIndex] = lContainer;
  addToEndOfViewTree(lView, lContainer);
  const viewRef = createForeignView(lContainer, 0);
  const node = createViewEffect(lView, lView[ENVIRONMENT].changeDetectionScheduler, () => {
    node.destroy();
    if (isDestroyed(lView)) {
      return;
    }
    const prevConsumer = setActiveConsumer(null);
    try {
      const resolvedProps = props ? props() : undefined;
      const context = getOrCreateInjectable(tNode, lView, FOREIGN_CONTEXT, 8);
      const [nodes, dispose] = foreignComponent[RENDER](resolvedProps, context ?? undefined);
      const tail = viewRef.tail;
      const parent = tail.parentNode;
      if (parent) {
        for (let i = 0; i < nodes.length; i++) {
          nativeInsertBefore(renderer, parent, nodes[i], tail, false);
        }
      }
      if (dispose) {
        viewRef.onDestroy(dispose);
      }
    } finally {
      setActiveConsumer(prevConsumer);
    }
  });
}
class ForeignContextInjector {
  context;
  constructor(context) {
    this.context = context;
  }
  get(token, notFoundValue) {
    return token === FOREIGN_CONTEXT ? this.context : notFoundValue;
  }
}
function resolveForeignContentContainer(index, foreignComponentConstIndex) {
  const lView = getLView();
  const adjustedIndex = index + HEADER_OFFSET;
  const lContainer = lView[adjustedIndex];
  ngDevMode && assertLContainer(lContainer);
  lContainer[FLAGS] |= 4;
  const tView = getTView();
  const tNode = tView.data[adjustedIndex];
  const foreignComponent = getConstant(tView.consts, foreignComponentConstIndex);
  ngDevMode && assertDefined(foreignComponent, 'Foreign component must be defined in constant pool.');
  return [lView, lContainer, tNode, foreignComponent];
}
function ɵɵforeignContent(index, foreignComponentConstIndex) {
  const [lView, lContainer, tNode, foreignComponent] = resolveForeignContentContainer(index, foreignComponentConstIndex);
  const adapter = foreignComponent[CONTENT_ADAPTER];
  const onDestroy = foreignComponent[ON_DESTROY];
  const getContext = foreignComponent[GET_CONTEXT];
  const producer = () => {
    const options = getContext ? {
      embeddedViewInjector: new ForeignContextInjector(getContext())
    } : undefined;
    const embeddedLView = createAndRenderEmbeddedLView(lView, tNode, null, options);
    addLViewToLContainer(lContainer, embeddedLView, lContainer.length - CONTAINER_HEADER_OFFSET, false);
    onDestroy(() => {
      if (!isDestroyed(embeddedLView)) {
        const embeddedLViewIndex = lContainer.indexOf(embeddedLView, CONTAINER_HEADER_OFFSET);
        ngDevMode && assertNotSame(embeddedLViewIndex, -1, 'Embedded view not found in container');
        removeLViewFromLContainer(lContainer, embeddedLViewIndex - CONTAINER_HEADER_OFFSET);
      }
    });
    const embeddedTView = embeddedLView[TVIEW$1];
    return collectNativeNodes(embeddedTView, embeddedLView, embeddedTView.firstChild, []);
  };
  return adapter(producer);
}
function ɵɵforeignContentFn(index, foreignComponentConstIndex) {
  const [lView, lContainer, tNode, foreignComponent] = resolveForeignContentContainer(index, foreignComponentConstIndex);
  const adapter = foreignComponent[CONTENT_ADAPTER];
  const onDestroy = foreignComponent[ON_DESTROY];
  const getContext = foreignComponent[GET_CONTEXT];
  return (...args) => {
    const producer = () => {
      const options = getContext ? {
        embeddedViewInjector: new ForeignContextInjector(getContext())
      } : undefined;
      const embeddedLView = createAndRenderEmbeddedLView(lView, tNode, args, options);
      addLViewToLContainer(lContainer, embeddedLView, lContainer.length - CONTAINER_HEADER_OFFSET, false);
      onDestroy(() => {
        if (!isDestroyed(embeddedLView)) {
          const embeddedLViewIndex = lContainer.indexOf(embeddedLView, CONTAINER_HEADER_OFFSET);
          ngDevMode && assertNotSame(embeddedLViewIndex, -1, 'Embedded view not found in container');
          removeLViewFromLContainer(lContainer, embeddedLViewIndex - CONTAINER_HEADER_OFFSET);
        }
      });
      const embeddedTView = embeddedLView[TVIEW$1];
      return collectNativeNodes(embeddedTView, embeddedLView, embeddedTView.firstChild, []);
    };
    return adapter(producer);
  };
}

function ɵɵgetCurrentView() {
  return getLView();
}

function ɵɵdomProperty(propName, value, sanitizer) {
  const lView = getLView();
  const bindingIndex = nextBindingIndex();
  if (bindingUpdated(lView, bindingIndex, value)) {
    const tView = getTView();
    const tNode = getSelectedTNode();
    setDomProperty(tNode, lView, propName, value, lView[RENDERER], sanitizer);
    ngDevMode && storePropertyBindingMetadata(tView.data, tNode, propName, bindingIndex);
  }
  return ɵɵdomProperty;
}
function ɵɵsyntheticHostProperty(propName, value, sanitizer) {
  const lView = getLView();
  const bindingIndex = nextBindingIndex();
  if (bindingUpdated(lView, bindingIndex, value)) {
    const tView = getTView();
    const tNode = getSelectedTNode();
    const currentDef = getCurrentDirectiveDef(tView.data);
    const renderer = loadComponentRenderer(currentDef, tNode, lView);
    setDomProperty(tNode, lView, propName, value, renderer, sanitizer);
    ngDevMode && storePropertyBindingMetadata(tView.data, tNode, propName, bindingIndex);
  }
  return ɵɵsyntheticHostProperty;
}

const u = undefined;
function plural(val) {
  const i = Math.floor(Math.abs(val)),
    v = val.toString().replace(/^[^.]*\.?/, '').length;
  if (i === 1 && v === 0) return 1;
  return 5;
}
var localeEn = ["en", [["a", "p"], ["AM", "PM"]], [["AM", "PM"]], [["S", "M", "T", "W", "T", "F", "S"], ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"], ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"], ["Su", "Mo", "Tu", "We", "Th", "Fr", "Sa"]], u, [["J", "F", "M", "A", "M", "J", "J", "A", "S", "O", "N", "D"], ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"]], u, [["B", "A"], ["BC", "AD"], ["Before Christ", "Anno Domini"]], 0, [6, 0], ["M/d/yy", "MMM d, y", "MMMM d, y", "EEEE, MMMM d, y"], ["h:mm a", "h:mm:ss a", "h:mm:ss a z", "h:mm:ss a zzzz"], ["{1}, {0}", u, u, u], [".", ",", ";", "%", "+", "-", "E", "×", "‰", "∞", "NaN", ":"], ["#,##0.###", "#,##0%", "¤#,##0.00", "#E0"], "USD", "$", "US Dollar", {}, "ltr", plural];

let LOCALE_DATA = /* @__PURE__ */Object.create(null);
function registerLocaleData(data, localeId, extraData) {
  if (typeof localeId !== 'string') {
    extraData = localeId;
    localeId = data[LocaleDataIndex.LocaleId];
  }
  localeId = localeId.toLowerCase().replace(/_/g, '-');
  LOCALE_DATA[localeId] = data;
  if (extraData) {
    LOCALE_DATA[localeId][LocaleDataIndex.ExtraData] = extraData;
  }
}
function findLocaleData(locale) {
  const normalizedLocale = normalizeLocale(locale);
  let match = getLocaleData(normalizedLocale);
  if (match) {
    return match;
  }
  const parentLocale = normalizedLocale.split('-')[0];
  match = getLocaleData(parentLocale);
  if (match) {
    return match;
  }
  if (parentLocale === 'en') {
    return localeEn;
  }
  throw new RuntimeError(701, ngDevMode && `Missing locale data for the locale "${locale}".`);
}
function getLocaleCurrencyCode(locale) {
  const data = findLocaleData(locale);
  return data[LocaleDataIndex.CurrencyCode] || null;
}
function getLocalePluralCase(locale) {
  const data = findLocaleData(locale);
  return data[LocaleDataIndex.PluralCase];
}
function getLocaleData(normalizedLocale) {
  if (!(normalizedLocale in LOCALE_DATA)) {
    const globalLocaleData = _global.ng && _global.ng.common && _global.ng.common.locales && _global.ng.common.locales[normalizedLocale];
    if (globalLocaleData !== undefined) {
      LOCALE_DATA[normalizedLocale] = globalLocaleData;
    }
    return globalLocaleData;
  }
  return LOCALE_DATA[normalizedLocale];
}
function unregisterAllLocaleData() {
  LOCALE_DATA = Object.create(null);
}
const LocaleDataIndex = {
  LocaleId: 0,
  DayPeriodsFormat: 1,
  DayPeriodsStandalone: 2,
  DaysFormat: 3,
  DaysStandalone: 4,
  MonthsFormat: 5,
  MonthsStandalone: 6,
  Eras: 7,
  FirstDayOfWeek: 8,
  WeekendRange: 9,
  DateFormat: 10,
  TimeFormat: 11,
  DateTimeFormat: 12,
  NumberSymbols: 13,
  NumberFormats: 14,
  CurrencyCode: 15,
  CurrencySymbol: 16,
  CurrencyName: 17,
  Currencies: 18,
  Directionality: 19,
  PluralCase: 20,
  ExtraData: 21
};
function normalizeLocale(locale) {
  return locale.toLowerCase().replace(/_/g, '-');
}

const pluralMapping = ['zero', 'one', 'two', 'few', 'many'];
function getPluralCase(value, locale) {
  const plural = getLocalePluralCase(locale)(parseInt(value, 10));
  const result = pluralMapping[plural];
  return result !== undefined ? result : 'other';
}
const DEFAULT_LOCALE_ID = 'en-US';
const USD_CURRENCY_CODE = 'USD';

const ELEMENT_MARKER = {
  marker: 'element'
};
const ICU_MARKER = {
  marker: 'ICU'
};
var I18nCreateOpCode;
(function (I18nCreateOpCode) {
  I18nCreateOpCode[I18nCreateOpCode["SHIFT"] = 2] = "SHIFT";
  I18nCreateOpCode[I18nCreateOpCode["APPEND_EAGERLY"] = 1] = "APPEND_EAGERLY";
  I18nCreateOpCode[I18nCreateOpCode["COMMENT"] = 2] = "COMMENT";
})(I18nCreateOpCode || (I18nCreateOpCode = {}));

let LOCALE_ID$1 = DEFAULT_LOCALE_ID;
function setLocaleId(localeId) {
  ngDevMode && assertDefined(localeId, `Expected localeId to be defined`);
  if (typeof localeId === 'string') {
    LOCALE_ID$1 = localeId.toLowerCase().replace(/_/g, '-');
  }
}
function getLocaleId() {
  return LOCALE_ID$1;
}

let changeMask = 0b0;
let changeMaskCounter = 0;
function setMaskBit(hasChange) {
  if (hasChange) {
    changeMask = changeMask | 1 << Math.min(changeMaskCounter, 31);
  }
  changeMaskCounter++;
}
function applyI18n(tView, lView, index) {
  try {
    if (changeMaskCounter > 0) {
      ngDevMode && assertDefined(tView, `tView should be defined`);
      const tI18n = tView.data[index];
      const updateOpCodes = Array.isArray(tI18n) ? tI18n : tI18n.update;
      const bindingsStartIndex = getBindingIndex() - changeMaskCounter - 1;
      applyUpdateOpCodes(tView, lView, updateOpCodes, bindingsStartIndex, changeMask);
    }
  } finally {
    changeMask = 0b0;
    changeMaskCounter = 0;
  }
}
function createNodeWithoutHydration(lView, textOrName, nodeType) {
  const renderer = lView[RENDERER];
  switch (nodeType) {
    case Node.COMMENT_NODE:
      return createCommentNode(renderer, textOrName);
    case Node.TEXT_NODE:
      return createTextNode(renderer, textOrName);
    case Node.ELEMENT_NODE:
      return createElementNode(renderer, textOrName, null);
  }
}
let _locateOrCreateNode = (lView, index, textOrName, nodeType) => {
  lastNodeWasCreated(true);
  return createNodeWithoutHydration(lView, textOrName, nodeType);
};
function locateOrCreateNodeImpl(lView, index, textOrName, nodeType) {
  const hydrationInfo = lView[HYDRATION];
  const noOffsetIndex = index - HEADER_OFFSET;
  const isNodeCreationMode = !isI18nHydrationSupportEnabled() || !hydrationInfo || isInSkipHydrationBlock$1() || isDisconnectedNode$1(hydrationInfo, noOffsetIndex);
  lastNodeWasCreated(isNodeCreationMode);
  if (isNodeCreationMode) {
    return createNodeWithoutHydration(lView, textOrName, nodeType);
  }
  const native = locateI18nRNodeByIndex(hydrationInfo, noOffsetIndex);
  ngDevMode && assertDefined(native, 'expected native element');
  ngDevMode && assertEqual(native.nodeType, nodeType, 'expected matching nodeType');
  ngDevMode && nodeType === Node.ELEMENT_NODE && assertEqual(native.tagName.toLowerCase(), textOrName.toLowerCase(), 'expecting matching tagName');
  ngDevMode && markRNodeAsClaimedByHydration(native);
  return native;
}
function enableLocateOrCreateI18nNodeImpl() {
  _locateOrCreateNode = locateOrCreateNodeImpl;
}
function applyCreateOpCodes(lView, createOpCodes, parentRNode, insertInFrontOf) {
  const renderer = lView[RENDERER];
  for (let i = 0; i < createOpCodes.length; i++) {
    const opCode = createOpCodes[i++];
    const text = createOpCodes[i];
    const isComment = (opCode & I18nCreateOpCode.COMMENT) === I18nCreateOpCode.COMMENT;
    const appendNow = (opCode & I18nCreateOpCode.APPEND_EAGERLY) === I18nCreateOpCode.APPEND_EAGERLY;
    const index = opCode >>> I18nCreateOpCode.SHIFT;
    let rNode = lView[index];
    let lastNodeWasCreated = false;
    if (rNode === null) {
      rNode = lView[index] = _locateOrCreateNode(lView, index, text, isComment ? Node.COMMENT_NODE : Node.TEXT_NODE);
      lastNodeWasCreated = wasLastNodeCreated();
    }
    if (appendNow && parentRNode !== null && lastNodeWasCreated) {
      nativeInsertBefore(renderer, parentRNode, rNode, insertInFrontOf, false);
    }
  }
}
function applyMutableOpCodes(tView, mutableOpCodes, lView, anchorRNode) {
  ngDevMode && assertDomNode(anchorRNode);
  const renderer = lView[RENDERER];
  let rootIdx = null;
  let rootRNode;
  for (let i = 0; i < mutableOpCodes.length; i++) {
    const opCode = mutableOpCodes[i];
    if (typeof opCode == 'string') {
      const textNodeIndex = mutableOpCodes[++i];
      if (lView[textNodeIndex] === null) {
        ngDevMode && assertIndexInRange(lView, textNodeIndex);
        lView[textNodeIndex] = _locateOrCreateNode(lView, textNodeIndex, opCode, Node.TEXT_NODE);
      }
    } else if (typeof opCode == 'number') {
      switch (opCode & 1) {
        case 0:
          const parentIdx = getParentFromIcuCreateOpCode(opCode);
          if (rootIdx === null) {
            rootIdx = parentIdx;
            rootRNode = renderer.parentNode(anchorRNode);
          }
          let insertInFrontOf;
          let parentRNode;
          if (parentIdx === rootIdx) {
            insertInFrontOf = anchorRNode;
            parentRNode = rootRNode;
          } else {
            insertInFrontOf = null;
            parentRNode = unwrapRNode(lView[parentIdx]);
          }
          if (parentRNode !== null) {
            ngDevMode && assertDomNode(parentRNode);
            const refIdx = getRefFromIcuCreateOpCode(opCode);
            ngDevMode && assertGreaterThan(refIdx, HEADER_OFFSET, 'Missing ref');
            const child = lView[refIdx];
            ngDevMode && assertDomNode(child);
            nativeInsertBefore(renderer, parentRNode, child, insertInFrontOf, false);
            const tIcu = getTIcu(tView, refIdx);
            if (tIcu !== null && typeof tIcu === 'object') {
              ngDevMode && assertTIcu(tIcu);
              const caseIndex = getCurrentICUCaseIndex(tIcu, lView);
              if (caseIndex !== null) {
                applyMutableOpCodes(tView, tIcu.create[caseIndex], lView, lView[tIcu.anchorIdx]);
              }
            }
          }
          break;
        case 1:
          const elementNodeIndex = opCode >>> 1;
          const attrName = mutableOpCodes[++i];
          const attrValue = mutableOpCodes[++i];
          setElementAttribute(renderer, getNativeByIndex(elementNodeIndex, lView), null, null, attrName, attrValue, null);
          break;
        default:
          if (ngDevMode) {
            throw new RuntimeError(700, `Unable to determine the type of mutate operation for "${opCode}"`);
          }
      }
    } else {
      switch (opCode) {
        case ICU_MARKER:
          const commentValue = mutableOpCodes[++i];
          const commentNodeIndex = mutableOpCodes[++i];
          if (lView[commentNodeIndex] === null) {
            ngDevMode && assertEqual(typeof commentValue, 'string', `Expected "${commentValue}" to be a comment node value`);
            ngDevMode && assertIndexInExpandoRange(lView, commentNodeIndex);
            const commentRNode = lView[commentNodeIndex] = _locateOrCreateNode(lView, commentNodeIndex, commentValue, Node.COMMENT_NODE);
            attachPatchData(commentRNode, lView);
          }
          break;
        case ELEMENT_MARKER:
          const tagName = mutableOpCodes[++i];
          const elementNodeIndex = mutableOpCodes[++i];
          if (lView[elementNodeIndex] === null) {
            ngDevMode && assertEqual(typeof tagName, 'string', `Expected "${tagName}" to be an element node tag name`);
            ngDevMode && assertIndexInExpandoRange(lView, elementNodeIndex);
            const elementRNode = lView[elementNodeIndex] = _locateOrCreateNode(lView, elementNodeIndex, tagName, Node.ELEMENT_NODE);
            attachPatchData(elementRNode, lView);
          }
          break;
        default:
          ngDevMode && throwError(`Unable to determine the type of mutate operation for "${opCode}"`);
      }
    }
  }
}
function applyUpdateOpCodes(tView, lView, updateOpCodes, bindingsStartIndex, changeMask) {
  for (let i = 0; i < updateOpCodes.length; i++) {
    const checkBit = updateOpCodes[i];
    const skipCodes = updateOpCodes[++i];
    if (checkBit & changeMask) {
      let value = '';
      for (let j = i + 1; j <= i + skipCodes; j++) {
        const opCode = updateOpCodes[j];
        if (typeof opCode == 'string') {
          value += opCode;
        } else if (typeof opCode == 'number') {
          if (opCode < 0) {
            value += renderStringify(lView[bindingsStartIndex - opCode]);
          } else {
            const nodeIndex = opCode >>> 2;
            switch (opCode & 3) {
              case 1:
                const propName = updateOpCodes[++j];
                const sanitizeFn = updateOpCodes[++j];
                const tNodeOrTagName = tView.data[nodeIndex];
                ngDevMode && assertDefined(tNodeOrTagName, 'Experting TNode or string');
                if (typeof tNodeOrTagName === 'string') {
                  setElementAttribute(lView[RENDERER], lView[nodeIndex], null, tNodeOrTagName, propName, value, sanitizeFn);
                } else {
                  const prevSelectedIndex = getSelectedIndex();
                  setSelectedIndex(nodeIndex);
                  try {
                    setPropertyAndInputs(tNodeOrTagName, lView, propName, value, lView[RENDERER], sanitizeFn);
                  } finally {
                    setSelectedIndex(prevSelectedIndex);
                  }
                }
                break;
              case 0:
                const rText = lView[nodeIndex];
                rText !== null && updateTextNode(lView[RENDERER], rText, value);
                break;
              case 2:
                applyIcuSwitchCase(tView, getTIcu(tView, nodeIndex), lView, value);
                break;
              case 3:
                applyIcuUpdateCase(tView, getTIcu(tView, nodeIndex), bindingsStartIndex, lView);
                break;
            }
          }
        }
      }
    } else {
      const opCode = updateOpCodes[i + 1];
      if (opCode > 0 && (opCode & 3) === 3) {
        const nodeIndex = opCode >>> 2;
        const tIcu = getTIcu(tView, nodeIndex);
        const currentIndex = lView[tIcu.currentCaseLViewIndex];
        if (currentIndex < 0) {
          applyIcuUpdateCase(tView, tIcu, bindingsStartIndex, lView);
        }
      }
    }
    i += skipCodes;
  }
}
function applyIcuUpdateCase(tView, tIcu, bindingsStartIndex, lView) {
  ngDevMode && assertIndexInRange(lView, tIcu.currentCaseLViewIndex);
  let activeCaseIndex = lView[tIcu.currentCaseLViewIndex];
  if (activeCaseIndex !== null) {
    let mask = changeMask;
    if (activeCaseIndex < 0) {
      activeCaseIndex = lView[tIcu.currentCaseLViewIndex] = ~activeCaseIndex;
      mask = -1;
    }
    applyUpdateOpCodes(tView, lView, tIcu.update[activeCaseIndex], bindingsStartIndex, mask);
  }
}
function applyIcuSwitchCase(tView, tIcu, lView, value) {
  const caseIndex = getCaseIndex(tIcu, value);
  let activeCaseIndex = getCurrentICUCaseIndex(tIcu, lView);
  if (activeCaseIndex !== caseIndex) {
    applyIcuSwitchCaseRemove(tView, tIcu, lView);
    lView[tIcu.currentCaseLViewIndex] = caseIndex === null ? null : ~caseIndex;
    if (caseIndex !== null) {
      const anchorRNode = lView[tIcu.anchorIdx];
      if (anchorRNode) {
        ngDevMode && assertDomNode(anchorRNode);
        applyMutableOpCodes(tView, tIcu.create[caseIndex], lView, anchorRNode);
      }
      claimDehydratedIcuCase(lView, tIcu.anchorIdx, caseIndex);
    }
  }
}
function applyIcuSwitchCaseRemove(tView, tIcu, lView) {
  let activeCaseIndex = getCurrentICUCaseIndex(tIcu, lView);
  if (activeCaseIndex !== null) {
    const removeCodes = tIcu.remove[activeCaseIndex];
    for (let i = 0; i < removeCodes.length; i++) {
      const nodeOrIcuIndex = removeCodes[i];
      if (nodeOrIcuIndex > 0) {
        const rNode = getNativeByIndex(nodeOrIcuIndex, lView);
        rNode !== null && nativeRemoveNode(lView[RENDERER], rNode);
      } else {
        applyIcuSwitchCaseRemove(tView, getTIcu(tView, ~nodeOrIcuIndex), lView);
      }
    }
  }
}
function getCaseIndex(icuExpression, bindingValue) {
  let index = icuExpression.cases.indexOf(bindingValue);
  if (index === -1) {
    switch (icuExpression.type) {
      case 1:
        {
          const resolvedCase = getPluralCase(bindingValue, getLocaleId());
          index = icuExpression.cases.indexOf(resolvedCase);
          if (index === -1 && resolvedCase !== 'other') {
            index = icuExpression.cases.indexOf('other');
          }
          break;
        }
      case 0:
        {
          index = icuExpression.cases.indexOf('other');
          break;
        }
    }
  }
  return index === -1 ? null : index;
}

function i18nCreateOpCodesToString(opcodes) {
  const createOpCodes = opcodes || (Array.isArray(this) ? this : []);
  let lines = [];
  for (let i = 0; i < createOpCodes.length; i++) {
    const opCode = createOpCodes[i++];
    const text = createOpCodes[i];
    const isComment = (opCode & I18nCreateOpCode.COMMENT) === I18nCreateOpCode.COMMENT;
    const appendNow = (opCode & I18nCreateOpCode.APPEND_EAGERLY) === I18nCreateOpCode.APPEND_EAGERLY;
    const index = opCode >>> I18nCreateOpCode.SHIFT;
    lines.push(`lView[${index}] = document.${isComment ? 'createComment' : 'createText'}(${JSON.stringify(text)});`);
    if (appendNow) {
      lines.push(`parent.appendChild(lView[${index}]);`);
    }
  }
  return lines;
}
function i18nUpdateOpCodesToString(opcodes) {
  const parser = new OpCodeParser(opcodes || (Array.isArray(this) ? this : []));
  let lines = [];
  function consumeOpCode(value) {
    const ref = value >>> 2;
    const opCode = value & 3;
    switch (opCode) {
      case 0:
        return `(lView[${ref}] as Text).textContent = $$$`;
      case 1:
        const attrName = parser.consumeString();
        const sanitizationFn = parser.consumeFunction();
        const value = sanitizationFn ? `(${sanitizationFn})($$$)` : '$$$';
        return `(lView[${ref}] as Element).setAttribute('${attrName}', ${value})`;
      case 2:
        return `icuSwitchCase(${ref}, $$$)`;
      case 3:
        return `icuUpdateCase(${ref})`;
    }
    throw new Error('unexpected OpCode');
  }
  while (parser.hasMore()) {
    let mask = parser.consumeNumber();
    let size = parser.consumeNumber();
    const end = parser.i + size;
    const statements = [];
    let statement = '';
    while (parser.i < end) {
      let value = parser.consumeNumberOrString();
      if (typeof value === 'string') {
        statement += value;
      } else if (value < 0) {
        statement += '${lView[i' + value + ']}';
      } else {
        const opCodeText = consumeOpCode(value);
        statements.push(opCodeText.replace('$$$', '`' + statement + '`') + ';');
        statement = '';
      }
    }
    lines.push(`if (mask & 0b${mask.toString(2)}) { ${statements.join(' ')} }`);
  }
  return lines;
}
function icuCreateOpCodesToString(opcodes) {
  const parser = new OpCodeParser(opcodes || (Array.isArray(this) ? this : []));
  let lines = [];
  function consumeOpCode(opCode) {
    const parent = getParentFromIcuCreateOpCode(opCode);
    const ref = getRefFromIcuCreateOpCode(opCode);
    switch (getInstructionFromIcuCreateOpCode(opCode)) {
      case 0:
        return `(lView[${parent}] as Element).appendChild(lView[${lastRef}])`;
      case 1:
        return `(lView[${ref}] as Element).setAttribute("${parser.consumeString()}", "${parser.consumeString()}")`;
    }
    throw new Error('Unexpected OpCode: ' + getInstructionFromIcuCreateOpCode(opCode));
  }
  let lastRef = -1;
  while (parser.hasMore()) {
    let value = parser.consumeNumberStringOrMarker();
    if (value === ICU_MARKER) {
      const text = parser.consumeString();
      lastRef = parser.consumeNumber();
      lines.push(`lView[${lastRef}] = document.createComment("${text}")`);
    } else if (value === ELEMENT_MARKER) {
      const text = parser.consumeString();
      lastRef = parser.consumeNumber();
      lines.push(`lView[${lastRef}] = document.createElement("${text}")`);
    } else if (typeof value === 'string') {
      lastRef = parser.consumeNumber();
      lines.push(`lView[${lastRef}] = document.createTextNode("${value}")`);
    } else if (typeof value === 'number') {
      const line = consumeOpCode(value);
      line && lines.push(line);
    } else {
      throw new Error('Unexpected value');
    }
  }
  return lines;
}
function i18nRemoveOpCodesToString(opcodes) {
  const removeCodes = opcodes || (Array.isArray(this) ? this : []);
  let lines = [];
  for (let i = 0; i < removeCodes.length; i++) {
    const nodeOrIcuIndex = removeCodes[i];
    if (nodeOrIcuIndex > 0) {
      lines.push(`remove(lView[${nodeOrIcuIndex}])`);
    } else {
      lines.push(`removeNestedICU(${~nodeOrIcuIndex})`);
    }
  }
  return lines;
}
class OpCodeParser {
  i = 0;
  codes;
  constructor(codes) {
    this.codes = codes;
  }
  hasMore() {
    return this.i < this.codes.length;
  }
  consumeNumber() {
    let value = this.codes[this.i++];
    assertNumber(value, 'expecting number in OpCode');
    return value;
  }
  consumeString() {
    let value = this.codes[this.i++];
    assertString(value, 'expecting string in OpCode');
    return value;
  }
  consumeFunction() {
    let value = this.codes[this.i++];
    if (value === null || typeof value === 'function') {
      return value;
    }
    throw new Error('expecting function in OpCode');
  }
  consumeNumberOrString() {
    let value = this.codes[this.i++];
    if (typeof value === 'string') {
      return value;
    }
    assertNumber(value, 'expecting number or string in OpCode');
    return value;
  }
  consumeNumberStringOrMarker() {
    let value = this.codes[this.i++];
    if (typeof value === 'string' || typeof value === 'number' || value == ICU_MARKER || value == ELEMENT_MARKER) {
      return value;
    }
    assertNumber(value, 'expecting number, string, ICU_MARKER or ELEMENT_MARKER in OpCode');
    return value;
  }
}

const BINDING_REGEXP = /�(\d+):?\d*�/gi;
const ICU_REGEXP = /({\s*�\d+:?\d*�\s*,\s*\S{6}\s*,[\s\S]*})/gi;
const NESTED_ICU = /�(\d+)�/;
const ICU_BLOCK_REGEXP = /^\s*(�\d+:?\d*�)\s*,\s*(select|plural)\s*,/;
const MARKER = `�`;
const SUBTEMPLATE_REGEXP = /�\/?\*(\d+:\d+)�/gi;
const PH_REGEXP = /�(\/?[#*]\d+):?\d*�/gi;
const NGSP_UNICODE_REGEXP = /\uE500/g;
function replaceNgsp(value) {
  return value.replace(NGSP_UNICODE_REGEXP, ' ');
}
function attachDebugGetter(obj, debugGetter) {
  if (ngDevMode) {
    Object.defineProperty(obj, 'debug', {
      get: debugGetter,
      enumerable: false
    });
  } else {
    throw new Error('This method should be guarded with `ngDevMode` so that it can be tree shaken in production!');
  }
}
function i18nStartFirstCreatePass(tView, parentTNodeIndex, lView, index, message, subTemplateIndex) {
  const rootTNode = getCurrentParentTNode();
  const createOpCodes = [];
  const updateOpCodes = [];
  const existingTNodeStack = [[]];
  const astStack = [[]];
  if (ngDevMode) {
    attachDebugGetter(createOpCodes, i18nCreateOpCodesToString);
    attachDebugGetter(updateOpCodes, i18nUpdateOpCodesToString);
  }
  message = getTranslationForTemplate(message, subTemplateIndex);
  const msgParts = replaceNgsp(message).split(PH_REGEXP);
  for (let i = 0; i < msgParts.length; i++) {
    let value = msgParts[i];
    if ((i & 1) === 0) {
      const parts = i18nParseTextIntoPartsAndICU(value);
      for (let j = 0; j < parts.length; j++) {
        let part = parts[j];
        if ((j & 1) === 0) {
          const text = part;
          ngDevMode && assertString(text, 'Parsed ICU part should be string');
          if (text !== '') {
            i18nStartFirstCreatePassProcessTextNode(astStack[0], tView, rootTNode, existingTNodeStack[0], createOpCodes, updateOpCodes, lView, text);
          }
        } else {
          const icuExpression = part;
          if (typeof icuExpression !== 'object') {
            throw new Error(`Unable to parse ICU expression in "${message}" message.`);
          }
          const icuContainerTNode = createTNodeAndAddOpCode(tView, rootTNode, existingTNodeStack[0], lView, createOpCodes, ngDevMode ? `ICU ${index}:${icuExpression.mainBinding}` : '', true);
          const icuNodeIndex = icuContainerTNode.index;
          ngDevMode && assertGreaterThanOrEqual(icuNodeIndex, HEADER_OFFSET, 'Index must be in absolute LView offset');
          icuStart(astStack[0], tView, lView, updateOpCodes, parentTNodeIndex, icuExpression, icuNodeIndex);
        }
      }
    } else {
      const isClosing = value.charCodeAt(0) === 47;
      const type = value.charCodeAt(isClosing ? 1 : 0);
      ngDevMode && assertOneOf(type, 42, 35);
      const index = HEADER_OFFSET + Number.parseInt(value.substring(isClosing ? 2 : 1));
      if (isClosing) {
        existingTNodeStack.shift();
        astStack.shift();
        setCurrentTNode(getCurrentParentTNode(), false);
      } else {
        const tNode = createTNodePlaceholder(tView, existingTNodeStack[0], index);
        existingTNodeStack.unshift([]);
        setCurrentTNode(tNode, true);
        const placeholderNode = {
          kind: 2,
          index,
          children: [],
          type: type === 35 ? 0 : 1
        };
        astStack[0].push(placeholderNode);
        astStack.unshift(placeholderNode.children);
      }
    }
  }
  tView.data[index] = {
    create: createOpCodes,
    update: updateOpCodes,
    ast: astStack[0],
    parentTNodeIndex
  };
}
function createTNodeAndAddOpCode(tView, rootTNode, existingTNodes, lView, createOpCodes, text, isICU) {
  const i18nNodeIdx = allocExpando(tView, lView, 1, null);
  let opCode = i18nNodeIdx << I18nCreateOpCode.SHIFT;
  let parentTNode = getCurrentParentTNode();
  if (rootTNode === parentTNode) {
    parentTNode = null;
  }
  if (parentTNode === null) {
    opCode |= I18nCreateOpCode.APPEND_EAGERLY;
  }
  if (isICU) {
    opCode |= I18nCreateOpCode.COMMENT;
    ensureIcuContainerVisitorLoaded(loadIcuContainerVisitor);
  }
  createOpCodes.push(opCode, text === null ? '' : text);
  const tNode = createTNodeAtIndex(tView, i18nNodeIdx, isICU ? 32 : 1, text === null ? ngDevMode ? '{{?}}' : '' : text, null);
  addTNodeAndUpdateInsertBeforeIndex(existingTNodes, tNode);
  const tNodeIdx = tNode.index;
  setCurrentTNode(tNode, false);
  if (parentTNode !== null && rootTNode !== parentTNode) {
    setTNodeInsertBeforeIndex(parentTNode, tNodeIdx);
  }
  return tNode;
}
function i18nStartFirstCreatePassProcessTextNode(ast, tView, rootTNode, existingTNodes, createOpCodes, updateOpCodes, lView, text) {
  const hasBinding = text.match(BINDING_REGEXP);
  const tNode = createTNodeAndAddOpCode(tView, rootTNode, existingTNodes, lView, createOpCodes, hasBinding ? null : text, false);
  const index = tNode.index;
  if (hasBinding) {
    generateBindingUpdateOpCodes(updateOpCodes, text, index, null, 0, null);
  }
  ast.push({
    kind: 0,
    index
  });
}
function i18nAttributesFirstPass(tView, index, values) {
  const previousElement = getCurrentTNode();
  const previousElementIndex = previousElement.index;
  const updateOpCodes = [];
  if (ngDevMode) {
    attachDebugGetter(updateOpCodes, i18nUpdateOpCodesToString);
  }
  if (tView.firstCreatePass && tView.data[index] === null) {
    for (let i = 0; i < values.length; i += 2) {
      const attrName = values[i];
      const message = values[i + 1];
      if (message !== '') {
        if (ICU_REGEXP.test(message)) {
          throw new Error(`ICU expressions are not supported in attributes. Message: "${message}".`);
        }
        const tagName = previousElement.namespace ? `:${previousElement.namespace}:${previousElement.value}` : previousElement.value;
        generateBindingUpdateOpCodes(updateOpCodes, message, previousElementIndex, attrName, countBindings(updateOpCodes), i18nResolveSanitizer(attrName, tagName));
      }
    }
    tView.data[index] = updateOpCodes;
  }
}
function generateBindingUpdateOpCodes(updateOpCodes, str, destinationNode, attrName, bindingStart, sanitizeFn) {
  ngDevMode && assertGreaterThanOrEqual(destinationNode, HEADER_OFFSET, 'Index must be in absolute LView offset');
  const maskIndex = updateOpCodes.length;
  const sizeIndex = maskIndex + 1;
  updateOpCodes.push(null, null);
  const startIndex = maskIndex + 2;
  if (ngDevMode) {
    attachDebugGetter(updateOpCodes, i18nUpdateOpCodesToString);
  }
  const textParts = str.split(BINDING_REGEXP);
  let mask = 0;
  for (let j = 0; j < textParts.length; j++) {
    const textValue = textParts[j];
    if (j & 1) {
      const bindingIndex = bindingStart + parseInt(textValue, 10);
      updateOpCodes.push(-1 - bindingIndex);
      mask = mask | toMaskBit(bindingIndex);
    } else if (textValue !== '') {
      updateOpCodes.push(textValue);
    }
  }
  updateOpCodes.push(destinationNode << 2 | (attrName ? 1 : 0));
  if (attrName) {
    updateOpCodes.push(attrName, sanitizeFn);
  }
  updateOpCodes[maskIndex] = mask;
  updateOpCodes[sizeIndex] = updateOpCodes.length - startIndex;
  return mask;
}
function countBindings(opCodes) {
  let count = 0;
  for (let i = 0; i < opCodes.length; i++) {
    const opCode = opCodes[i];
    if (typeof opCode === 'number' && opCode < 0) {
      count++;
    }
  }
  return count;
}
function toMaskBit(bindingIndex) {
  return 1 << Math.min(bindingIndex, 31);
}
function removeInnerTemplateTranslation(message) {
  let match;
  let res = '';
  let index = 0;
  let inTemplate = false;
  let tagMatched;
  while ((match = SUBTEMPLATE_REGEXP.exec(message)) !== null) {
    if (!inTemplate) {
      res += message.substring(index, match.index + match[0].length);
      tagMatched = match[1];
      inTemplate = true;
    } else {
      if (match[0] === `${MARKER}/*${tagMatched}${MARKER}`) {
        index = match.index;
        inTemplate = false;
      }
    }
  }
  ngDevMode && assertEqual(inTemplate, false, `Tag mismatch: unable to find the end of the sub-template in the translation "${message}"`);
  res += message.slice(index);
  return res;
}
function getTranslationForTemplate(message, subTemplateIndex) {
  if (isRootTemplateMessage(subTemplateIndex)) {
    return removeInnerTemplateTranslation(message);
  } else {
    const start = message.indexOf(`:${subTemplateIndex}${MARKER}`) + 2 + subTemplateIndex.toString().length;
    const end = message.search(new RegExp(`${MARKER}\\/\\*\\d+:${subTemplateIndex}${MARKER}`));
    return removeInnerTemplateTranslation(message.substring(start, end));
  }
}
function icuStart(ast, tView, lView, updateOpCodes, parentIdx, icuExpression, anchorIdx) {
  ngDevMode && assertDefined(icuExpression, 'ICU expression must be defined');
  let bindingMask = 0;
  const tIcu = {
    type: icuExpression.type,
    currentCaseLViewIndex: allocExpando(tView, lView, 1, null),
    anchorIdx,
    cases: [],
    create: [],
    remove: [],
    update: []
  };
  addUpdateIcuSwitch(updateOpCodes, icuExpression, anchorIdx);
  setTIcu(tView, anchorIdx, tIcu);
  const values = icuExpression.values;
  const cases = [];
  for (let i = 0; i < values.length; i++) {
    const valueArr = values[i];
    const nestedIcus = [];
    for (let j = 0; j < valueArr.length; j++) {
      const value = valueArr[j];
      if (typeof value !== 'string') {
        const icuIndex = nestedIcus.push(value) - 1;
        valueArr[j] = `<!--�${icuIndex}�-->`;
      }
    }
    const caseAst = [];
    cases.push(caseAst);
    bindingMask = parseIcuCase(caseAst, tView, tIcu, lView, updateOpCodes, parentIdx, icuExpression.cases[i], valueArr.join(''), nestedIcus) | bindingMask;
  }
  if (bindingMask) {
    addUpdateIcuUpdate(updateOpCodes, bindingMask, anchorIdx);
  }
  ast.push({
    kind: 3,
    index: anchorIdx,
    cases,
    currentCaseLViewIndex: tIcu.currentCaseLViewIndex
  });
}
function parseICUBlock(pattern) {
  const cases = [];
  const values = [];
  let icuType = 1;
  let mainBinding = 0;
  pattern = pattern.replace(ICU_BLOCK_REGEXP, function (str, binding, type) {
    if (type === 'select') {
      icuType = 0;
    } else {
      icuType = 1;
    }
    mainBinding = parseInt(binding.slice(1), 10);
    return '';
  });
  const parts = i18nParseTextIntoPartsAndICU(pattern);
  for (let pos = 0; pos < parts.length;) {
    let key = parts[pos++].trim();
    if (icuType === 1) {
      key = key.replace(/\s*(?:=)?(\w+)\s*/, '$1');
    }
    if (key.length) {
      cases.push(key);
    }
    const blocks = i18nParseTextIntoPartsAndICU(parts[pos++]);
    if (cases.length > values.length) {
      values.push(blocks);
    }
  }
  return {
    type: icuType,
    mainBinding: mainBinding,
    cases,
    values
  };
}
function i18nParseTextIntoPartsAndICU(pattern) {
  if (!pattern) {
    return [];
  }
  let prevPos = 0;
  const braceStack = [];
  const results = [];
  const braces = /[{}]/g;
  braces.lastIndex = 0;
  let match;
  while (match = braces.exec(pattern)) {
    const pos = match.index;
    if (match[0] == '}') {
      braceStack.pop();
      if (braceStack.length == 0) {
        const block = pattern.substring(prevPos, pos);
        if (ICU_BLOCK_REGEXP.test(block)) {
          results.push(parseICUBlock(block));
        } else {
          results.push(block);
        }
        prevPos = pos + 1;
      }
    } else {
      if (braceStack.length == 0) {
        const substring = pattern.substring(prevPos, pos);
        results.push(substring);
        prevPos = pos + 1;
      }
      braceStack.push('{');
    }
  }
  const substring = pattern.substring(prevPos);
  results.push(substring);
  return results;
}
function parseIcuCase(ast, tView, tIcu, lView, updateOpCodes, parentIdx, caseName, unsafeCaseHtml, nestedIcus) {
  const create = [];
  const remove = [];
  const update = [];
  if (ngDevMode) {
    attachDebugGetter(create, icuCreateOpCodesToString);
    attachDebugGetter(remove, i18nRemoveOpCodesToString);
    attachDebugGetter(update, i18nUpdateOpCodesToString);
  }
  tIcu.cases.push(caseName);
  tIcu.create.push(create);
  tIcu.remove.push(remove);
  tIcu.update.push(update);
  const inertBodyHelper = getInertBodyHelper(getDocument());
  const inertBodyElement = inertBodyHelper.getInertBodyElement(unsafeCaseHtml);
  ngDevMode && assertDefined(inertBodyElement, 'Unable to generate inert body element');
  const inertRootNode = getTemplateContent(inertBodyElement) || inertBodyElement;
  if (inertRootNode) {
    return walkIcuTree(ast, tView, tIcu, lView, updateOpCodes, create, remove, update, inertRootNode, parentIdx, nestedIcus, 0);
  } else {
    return 0;
  }
}
function walkIcuTree(ast, tView, tIcu, lView, sharedUpdateOpCodes, create, remove, update, parentNode, parentIdx, nestedIcus, depth) {
  let bindingMask = 0;
  let currentNode = parentNode.firstChild;
  while (currentNode) {
    const newIndex = allocExpando(tView, lView, 1, null);
    switch (currentNode.nodeType) {
      case Node.ELEMENT_NODE:
        const element = currentNode;
        const tagName = element.tagName.toLowerCase();
        if (Object.hasOwn(VALID_ELEMENTS, tagName)) {
          addCreateNodeAndAppend(create, ELEMENT_MARKER, tagName, parentIdx, newIndex);
          tView.data[newIndex] = tagName;
          const elAttrs = element.attributes;
          for (let i = 0; i < elAttrs.length; i++) {
            const attr = elAttrs.item(i);
            const lowerAttrName = attr.name.toLowerCase();
            const hasBinding = !!attr.value.match(BINDING_REGEXP);
            const namespaceUri = element.namespaceURI;
            const namespace = namespaceUri && NAMESPACE_URIS[namespaceUri];
            const tagNameWithNamespace = namespace ? `:${namespace}:${tagName}` : tagName;
            if (hasBinding) {
              if (Object.hasOwn(VALID_ATTRS, lowerAttrName)) {
                generateBindingUpdateOpCodes(update, attr.value, newIndex, attr.name, 0, i18nResolveSanitizer(lowerAttrName, tagNameWithNamespace));
              } else {
                ngDevMode && console.warn(`WARNING: ignoring unsafe attribute value ` + `${lowerAttrName} on element ${tagName} ` + `(see ${XSS_SECURITY_URL})`);
              }
            } else if (VALID_ATTRS[lowerAttrName]) {
              let val = attr.value;
              const sanitizer = i18nResolveSanitizer(lowerAttrName, tagNameWithNamespace);
              if (sanitizer) {
                if (typeof ngDevMode !== 'undefined' && ngDevMode) {
                  console.warn(`WARNING: ignoring unsafe attribute ` + `${lowerAttrName} on element ${tagName} ` + `(see ${XSS_SECURITY_URL})`);
                }
                addCreateAttribute(create, newIndex, attr.name, 'unsafe:blocked');
              } else {
                addCreateAttribute(create, newIndex, attr.name, val);
              }
            } else {
              if (typeof ngDevMode !== 'undefined' && ngDevMode) {
                console.warn(`WARNING: ignoring unknown attribute name ` + `${lowerAttrName} on element ${tagName} ` + `(see ${XSS_SECURITY_URL})`);
              }
            }
          }
          const elementNode = {
            kind: 1,
            index: newIndex,
            children: []
          };
          ast.push(elementNode);
          bindingMask = walkIcuTree(elementNode.children, tView, tIcu, lView, sharedUpdateOpCodes, create, remove, update, currentNode, newIndex, nestedIcus, depth + 1) | bindingMask;
          addRemoveNode(remove, newIndex, depth);
        }
        break;
      case Node.TEXT_NODE:
        const value = currentNode.textContent || '';
        const hasBinding = value.match(BINDING_REGEXP);
        addCreateNodeAndAppend(create, null, hasBinding ? '' : value, parentIdx, newIndex);
        addRemoveNode(remove, newIndex, depth);
        if (hasBinding) {
          bindingMask = generateBindingUpdateOpCodes(update, value, newIndex, null, 0, null) | bindingMask;
        }
        ast.push({
          kind: 0,
          index: newIndex
        });
        break;
      case Node.COMMENT_NODE:
        const isNestedIcu = NESTED_ICU.exec(currentNode.textContent || '');
        if (isNestedIcu) {
          const nestedIcuIndex = parseInt(isNestedIcu[1], 10);
          const icuExpression = nestedIcus[nestedIcuIndex];
          addCreateNodeAndAppend(create, ICU_MARKER, ngDevMode ? `nested ICU ${nestedIcuIndex}` : '', parentIdx, newIndex);
          icuStart(ast, tView, lView, sharedUpdateOpCodes, parentIdx, icuExpression, newIndex);
          addRemoveNestedIcu(remove, newIndex, depth);
        }
        break;
    }
    currentNode = currentNode.nextSibling;
  }
  return bindingMask;
}
function addRemoveNode(remove, index, depth) {
  if (depth === 0) {
    remove.push(index);
  }
}
function addRemoveNestedIcu(remove, index, depth) {
  if (depth === 0) {
    remove.push(~index);
    remove.push(index);
  }
}
function addUpdateIcuSwitch(update, icuExpression, index) {
  update.push(toMaskBit(icuExpression.mainBinding), 2, -1 - icuExpression.mainBinding, index << 2 | 2);
}
function addUpdateIcuUpdate(update, bindingMask, index) {
  update.push(bindingMask, 1, index << 2 | 3);
}
function addCreateNodeAndAppend(create, marker, text, appendToParentIdx, createAtIdx) {
  if (marker !== null) {
    create.push(marker);
  }
  create.push(text, createAtIdx, icuCreateOpCode(0, appendToParentIdx, createAtIdx));
}
function addCreateAttribute(create, newIndex, attrName, attrValue) {
  create.push(newIndex << 1 | 1, attrName, attrValue);
}
function i18nResolveSanitizer(attrName, tagName) {
  let schemaContext;
  if (tagName) {
    const [ns, name] = splitNsName(tagName, false);
    schemaContext = checkSecurityContext(name, attrName, ns);
  } else {
    schemaContext = checkSecurityContext('*', attrName);
  }
  switch (schemaContext) {
    case SecurityContext.HTML:
      return ɵɵsanitizeHtml;
    case SecurityContext.STYLE:
      return ɵɵsanitizeStyle;
    case SecurityContext.SCRIPT:
      return ɵɵsanitizeScript;
    case SecurityContext.URL:
      return _sanitizeUrl;
    case SecurityContext.RESOURCE_URL:
      return ɵɵsanitizeResourceUrl;
    case SecurityContext.ATTRIBUTE_NO_BINDING:
      return ɵɵvalidateAttribute;
    default:
      return null;
  }
}

const ROOT_TEMPLATE_ID = 0;
const PP_MULTI_VALUE_PLACEHOLDERS_REGEXP = /\[(�.+?�?)\]/;
const PP_PLACEHOLDERS_REGEXP = /\[(�.+?�?)\]|(�\/?\*\d+:\d+�)/g;
const PP_ICU_VARS_REGEXP = /({\s*)(VAR_(PLURAL|SELECT)(_\d+)?)(\s*,)/g;
const PP_ICU_PLACEHOLDERS_REGEXP = /{([A-Z0-9_]+)}/g;
const PP_ICUS_REGEXP = /�I18N_EXP_(ICU(_\d+)?)�/g;
const PP_CLOSE_TEMPLATE_REGEXP = /\/\*/;
const PP_TEMPLATE_ID_REGEXP = /\d+\:(\d+)/;
function i18nPostprocess(message, replacements = {}) {
  let result = message;
  if (PP_MULTI_VALUE_PLACEHOLDERS_REGEXP.test(message)) {
    const matches = {};
    const templateIdsStack = [ROOT_TEMPLATE_ID];
    result = result.replace(PP_PLACEHOLDERS_REGEXP, (m, phs, tmpl) => {
      const content = phs || tmpl;
      const placeholders = matches[content] || [];
      if (!placeholders.length) {
        content.split('|').forEach(placeholder => {
          const match = placeholder.match(PP_TEMPLATE_ID_REGEXP);
          const templateId = match ? parseInt(match[1], 10) : ROOT_TEMPLATE_ID;
          const isCloseTemplateTag = PP_CLOSE_TEMPLATE_REGEXP.test(placeholder);
          placeholders.push([templateId, isCloseTemplateTag, placeholder]);
        });
        matches[content] = placeholders;
      }
      if (!placeholders.length) {
        throw new Error(`i18n postprocess: unmatched placeholder - ${content}`);
      }
      const currentTemplateId = templateIdsStack[templateIdsStack.length - 1];
      let idx = 0;
      for (let i = 0; i < placeholders.length; i++) {
        if (placeholders[i][0] === currentTemplateId) {
          idx = i;
          break;
        }
      }
      const [templateId, isCloseTemplateTag, placeholder] = placeholders[idx];
      if (isCloseTemplateTag) {
        templateIdsStack.pop();
      } else if (currentTemplateId !== templateId) {
        templateIdsStack.push(templateId);
      }
      placeholders.splice(idx, 1);
      return placeholder;
    });
  }
  if (!Object.keys(replacements).length) {
    return result;
  }
  result = result.replace(PP_ICU_VARS_REGEXP, (match, start, key, _type, _idx, end) => {
    return Object.hasOwn(replacements, key) ? `${start}${replacements[key]}${end}` : match;
  });
  result = result.replace(PP_ICU_PLACEHOLDERS_REGEXP, (match, key) => {
    return Object.hasOwn(replacements, key) ? replacements[key] : match;
  });
  result = result.replace(PP_ICUS_REGEXP, (match, key) => {
    if (Object.hasOwn(replacements, key)) {
      const list = replacements[key];
      if (!list.length) {
        throw new Error(`i18n postprocess: unmatched ICU - ${match} with key: ${key}`);
      }
      return list.shift();
    }
    return match;
  });
  return result;
}

function ɵɵi18nStart(index, messageIndex, subTemplateIndex = -1) {
  const tView = getTView();
  const lView = getLView();
  const adjustedIndex = HEADER_OFFSET + index;
  ngDevMode && assertDefined(tView, `tView should be defined`);
  const message = getConstant(tView.consts, messageIndex);
  const parentTNode = getCurrentParentTNode();
  if (tView.firstCreatePass) {
    i18nStartFirstCreatePass(tView, parentTNode === null ? 0 : parentTNode.index, lView, adjustedIndex, message, subTemplateIndex);
  }
  if (tView.type === 2) {
    const componentLView = lView[DECLARATION_COMPONENT_VIEW];
    componentLView[FLAGS] |= 32;
  } else {
    lView[FLAGS] |= 32;
  }
  const tI18n = tView.data[adjustedIndex];
  const sameViewParentTNode = parentTNode === lView[T_HOST] ? null : parentTNode;
  const parentRNode = getClosestRElement(tView, sameViewParentTNode, lView);
  const insertInFrontOf = parentTNode && parentTNode.type & 8 ? lView[parentTNode.index] : null;
  prepareI18nBlockForHydration(lView, adjustedIndex, parentTNode, subTemplateIndex);
  applyCreateOpCodes(lView, tI18n.create, parentRNode, insertInFrontOf);
  setInI18nBlock(true);
}
function ɵɵi18nEnd() {
  setInI18nBlock(false);
}
function ɵɵi18n(index, messageIndex, subTemplateIndex) {
  ɵɵi18nStart(index, messageIndex, subTemplateIndex);
  ɵɵi18nEnd();
}
function ɵɵi18nAttributes(index, attrsIndex) {
  const tView = getTView();
  ngDevMode && assertDefined(tView, `tView should be defined`);
  const attrs = getConstant(tView.consts, attrsIndex);
  i18nAttributesFirstPass(tView, index + HEADER_OFFSET, attrs);
}
function ɵɵi18nExp(value) {
  const lView = getLView();
  setMaskBit(bindingUpdated(lView, nextBindingIndex(), value));
  return ɵɵi18nExp;
}
function ɵɵi18nApply(index) {
  applyI18n(getTView(), getLView(), index + HEADER_OFFSET);
}
function ɵɵi18nPostprocess(message, replacements = {}) {
  return i18nPostprocess(message, replacements);
}

function ɵɵlistener(eventName, listenerFn, eventTargetResolver) {
  const lView = getLView();
  const tView = getTView();
  const tNode = getCurrentTNode();
  listenerInternal(tView, lView, lView[RENDERER], tNode, eventName, listenerFn, eventTargetResolver);
  return ɵɵlistener;
}
function ɵɵsyntheticHostListener(eventName, listenerFn) {
  const tNode = getCurrentTNode();
  const lView = getLView();
  const tView = getTView();
  const currentDef = getCurrentDirectiveDef(tView.data);
  const renderer = loadComponentRenderer(currentDef, tNode, lView);
  listenerInternal(tView, lView, renderer, tNode, eventName, listenerFn);
  return ɵɵsyntheticHostListener;
}
function ɵɵdomListener(eventName, listenerFn, eventTargetResolver) {
  const lView = getLView();
  const tView = getTView();
  const tNode = getCurrentTNode();
  if (tNode.type & 3 || eventTargetResolver) {
    listenToDomEvent(tNode, tView, lView, eventTargetResolver, lView[RENDERER], eventName, listenerFn, wrapListener(tNode, lView, listenerFn));
  }
  return ɵɵdomListener;
}
function listenerInternal(tView, lView, renderer, tNode, eventName, listenerFn, eventTargetResolver) {
  ngDevMode && assertTNodeType(tNode, 3 | 12);
  let processOutputs = true;
  let wrappedListener = null;
  if (tNode.type & 3 || eventTargetResolver) {
    wrappedListener ??= wrapListener(tNode, lView, listenerFn);
    const hasCoalescedDomEvent = listenToDomEvent(tNode, tView, lView, eventTargetResolver, renderer, eventName, listenerFn, wrappedListener);
    if (hasCoalescedDomEvent) {
      processOutputs = false;
    }
  }
  if (processOutputs) {
    const outputConfig = tNode.outputs?.[eventName];
    const hostDirectiveOutputConfig = tNode.hostDirectiveOutputs?.[eventName];
    if (hostDirectiveOutputConfig && hostDirectiveOutputConfig.length) {
      for (let i = 0; i < hostDirectiveOutputConfig.length; i += 2) {
        const index = hostDirectiveOutputConfig[i];
        const lookupName = hostDirectiveOutputConfig[i + 1];
        wrappedListener ??= wrapListener(tNode, lView, listenerFn);
        listenToOutput(tNode, lView, index, lookupName, eventName, wrappedListener);
      }
    }
    if (outputConfig && outputConfig.length) {
      for (const index of outputConfig) {
        wrappedListener ??= wrapListener(tNode, lView, listenerFn);
        listenToOutput(tNode, lView, index, eventName, eventName, wrappedListener);
      }
    }
  }
}

function ɵɵnextContext(level = 1) {
  return nextContextImpl(level);
}

function matchingProjectionSlotIndex(tNode, projectionSlots) {
  let wildcardNgContentIndex = null;
  const ngProjectAsAttrVal = getProjectAsAttrValue(tNode);
  for (let i = 0; i < projectionSlots.length; i++) {
    const slotValue = projectionSlots[i];
    if (slotValue === '*') {
      wildcardNgContentIndex = i;
      continue;
    }
    if (ngProjectAsAttrVal === null ? isNodeMatchingSelectorList(tNode, slotValue, true) : isSelectorInSelectorList(ngProjectAsAttrVal, slotValue)) {
      return i;
    }
  }
  return wildcardNgContentIndex;
}
function ɵɵprojectionDef(projectionSlots) {
  const componentNode = getLView()[DECLARATION_COMPONENT_VIEW][T_HOST];
  if (!componentNode.projection) {
    const numProjectionSlots = projectionSlots ? projectionSlots.length : 1;
    const projectionHeads = componentNode.projection = newArray(numProjectionSlots, null);
    const tails = projectionHeads.slice();
    let componentChild = componentNode.child;
    while (componentChild !== null) {
      if (componentChild.type !== 128) {
        const slotIndex = projectionSlots ? matchingProjectionSlotIndex(componentChild, projectionSlots) : 0;
        if (slotIndex !== null) {
          if (tails[slotIndex]) {
            tails[slotIndex].projectionNext = componentChild;
          } else {
            projectionHeads[slotIndex] = componentChild;
          }
          tails[slotIndex] = componentChild;
        }
      }
      componentChild = componentChild.next;
    }
  }
}
function ɵɵprojection(nodeIndex, selectorIndex = 0, attrs, fallbackTemplateFn, fallbackDecls, fallbackVars) {
  const lView = getLView();
  const tView = getTView();
  const fallbackIndex = fallbackTemplateFn ? nodeIndex + 1 : null;
  if (fallbackIndex !== null) {
    declareNoDirectiveHostTemplate(lView, tView, fallbackIndex, fallbackTemplateFn, fallbackDecls, fallbackVars, null, attrs);
  }
  const tProjectionNode = getOrCreateTNode(tView, HEADER_OFFSET + nodeIndex, 16, null, attrs || null);
  if (tProjectionNode.projection === null) {
    tProjectionNode.projection = selectorIndex;
  }
  setCurrentTNodeAsNotParent();
  const hydrationInfo = lView[HYDRATION];
  const isNodeCreationMode = !hydrationInfo || isInSkipHydrationBlock$1();
  const componentHostNode = lView[DECLARATION_COMPONENT_VIEW][T_HOST];
  const isEmpty = componentHostNode.projection[tProjectionNode.projection] === null;
  if (isEmpty && fallbackIndex !== null) {
    insertFallbackContent(lView, tView, fallbackIndex);
  } else if (isNodeCreationMode && !isDetachedByI18n(tProjectionNode)) {
    applyProjection(tView, lView, tProjectionNode);
  }
}
function insertFallbackContent(lView, tView, fallbackIndex) {
  const adjustedIndex = HEADER_OFFSET + fallbackIndex;
  const fallbackTNode = tView.data[adjustedIndex];
  const fallbackLContainer = lView[adjustedIndex];
  ngDevMode && assertTNode(fallbackTNode);
  ngDevMode && assertLContainer(fallbackLContainer);
  const dehydratedView = findMatchingDehydratedView(fallbackLContainer, fallbackTNode.tView.ssrId);
  const fallbackLView = createAndRenderEmbeddedLView(lView, fallbackTNode, undefined, {
    dehydratedView
  });
  addLViewToLContainer(fallbackLContainer, fallbackLView, 0, shouldAddViewToDom(fallbackTNode, dehydratedView));
}

function ɵɵcontentQuery(directiveIndex, predicate, flags, read) {
  createContentQuery(directiveIndex, predicate, flags, read);
  return ɵɵcontentQuery;
}
function ɵɵviewQuery(predicate, flags, read) {
  createViewQuery(predicate, flags, read);
  return ɵɵviewQuery;
}
function ɵɵqueryRefresh(queryList) {
  const lView = getLView();
  const tView = getTView();
  const queryIndex = getCurrentQueryIndex();
  setCurrentQueryIndex(queryIndex + 1);
  const tQuery = getTQuery(tView, queryIndex);
  if (queryList.dirty && isCreationMode(lView) === ((tQuery.metadata.flags & 2) === 2)) {
    if (tQuery.matches === null) {
      queryList.reset([]);
    } else {
      const result = getQueryResults(lView, queryIndex);
      queryList.reset(result, unwrapElementRef);
      queryList.notifyOnChanges();
    }
    return true;
  }
  return false;
}
function ɵɵloadQuery() {
  return loadQueryInternal(getLView(), getCurrentQueryIndex());
}

function ɵɵcontentQuerySignal(directiveIndex, target, predicate, flags, read) {
  bindQueryToSignal(target, createContentQuery(directiveIndex, predicate, flags, read));
  return ɵɵcontentQuerySignal;
}
function ɵɵviewQuerySignal(target, predicate, flags, read) {
  bindQueryToSignal(target, createViewQuery(predicate, flags, read));
  return ɵɵviewQuerySignal;
}
function ɵɵqueryAdvance(indexOffset = 1) {
  setCurrentQueryIndex(getCurrentQueryIndex() + indexOffset);
}

function ɵɵreference(index) {
  const contextLView = getContextLView();
  return load(contextLView, HEADER_OFFSET + index);
}

function toTStylingRange(prev, next) {
  ngDevMode && assertNumberInRange(prev, 0, 32767);
  ngDevMode && assertNumberInRange(next, 0, 32767);
  return prev << 17 | next << 2;
}
function getTStylingRangePrev(tStylingRange) {
  ngDevMode && assertNumber(tStylingRange, 'expected number');
  return tStylingRange >> 17 & 32767;
}
function getTStylingRangePrevDuplicate(tStylingRange) {
  ngDevMode && assertNumber(tStylingRange, 'expected number');
  return (tStylingRange & 2) == 2;
}
function setTStylingRangePrev(tStylingRange, previous) {
  ngDevMode && assertNumber(tStylingRange, 'expected number');
  ngDevMode && assertNumberInRange(previous, 0, 32767);
  return tStylingRange & 131071 | previous << 17;
}
function setTStylingRangePrevDuplicate(tStylingRange) {
  ngDevMode && assertNumber(tStylingRange, 'expected number');
  return tStylingRange | 2;
}
function getTStylingRangeNext(tStylingRange) {
  ngDevMode && assertNumber(tStylingRange, 'expected number');
  return (tStylingRange & 131068) >> 2;
}
function setTStylingRangeNext(tStylingRange, next) {
  ngDevMode && assertNumber(tStylingRange, 'expected number');
  ngDevMode && assertNumberInRange(next, 0, 32767);
  return tStylingRange & -131069 | next << 2;
}
function getTStylingRangeNextDuplicate(tStylingRange) {
  ngDevMode && assertNumber(tStylingRange, 'expected number');
  return (tStylingRange & 1) === 1;
}
function setTStylingRangeNextDuplicate(tStylingRange) {
  ngDevMode && assertNumber(tStylingRange, 'expected number');
  return tStylingRange | 1;
}

function insertTStylingBinding(tData, tNode, tStylingKeyWithStatic, index, isHostBinding, isClassBinding) {
  ngDevMode && assertFirstUpdatePass(getTView());
  let tBindings = isClassBinding ? tNode.classBindings : tNode.styleBindings;
  let tmplHead = getTStylingRangePrev(tBindings);
  let tmplTail = getTStylingRangeNext(tBindings);
  tData[index] = tStylingKeyWithStatic;
  let isKeyDuplicateOfStatic = false;
  let tStylingKey;
  if (Array.isArray(tStylingKeyWithStatic)) {
    const staticKeyValueArray = tStylingKeyWithStatic;
    tStylingKey = staticKeyValueArray[1];
    if (tStylingKey === null || keyValueArrayIndexOf(staticKeyValueArray, tStylingKey) > 0) {
      isKeyDuplicateOfStatic = true;
    }
  } else {
    tStylingKey = tStylingKeyWithStatic;
  }
  if (isHostBinding) {
    const hasTemplateBindings = tmplTail !== 0;
    if (hasTemplateBindings) {
      const previousNode = getTStylingRangePrev(tData[tmplHead + 1]);
      tData[index + 1] = toTStylingRange(previousNode, tmplHead);
      if (previousNode !== 0) {
        tData[previousNode + 1] = setTStylingRangeNext(tData[previousNode + 1], index);
      }
      tData[tmplHead + 1] = setTStylingRangePrev(tData[tmplHead + 1], index);
    } else {
      tData[index + 1] = toTStylingRange(tmplHead, 0);
      if (tmplHead !== 0) {
        tData[tmplHead + 1] = setTStylingRangeNext(tData[tmplHead + 1], index);
      }
      tmplHead = index;
    }
  } else {
    tData[index + 1] = toTStylingRange(tmplTail, 0);
    ngDevMode && assertEqual(tmplHead !== 0 && tmplTail === 0, false, 'Adding template bindings after hostBindings is not allowed.');
    if (tmplHead === 0) {
      tmplHead = index;
    } else {
      tData[tmplTail + 1] = setTStylingRangeNext(tData[tmplTail + 1], index);
    }
    tmplTail = index;
  }
  if (isKeyDuplicateOfStatic) {
    tData[index + 1] = setTStylingRangePrevDuplicate(tData[index + 1]);
  }
  markDuplicates(tData, tStylingKey, index, true);
  markDuplicates(tData, tStylingKey, index, false);
  markDuplicateOfResidualStyling(tNode, tStylingKey, tData, index, isClassBinding);
  tBindings = toTStylingRange(tmplHead, tmplTail);
  if (isClassBinding) {
    tNode.classBindings = tBindings;
  } else {
    tNode.styleBindings = tBindings;
  }
}
function markDuplicateOfResidualStyling(tNode, tStylingKey, tData, index, isClassBinding) {
  const residual = isClassBinding ? tNode.residualClasses : tNode.residualStyles;
  if (residual != null && typeof tStylingKey == 'string' && keyValueArrayIndexOf(residual, tStylingKey) >= 0) {
    tData[index + 1] = setTStylingRangeNextDuplicate(tData[index + 1]);
  }
}
function markDuplicates(tData, tStylingKey, index, isPrevDir) {
  const tStylingAtIndex = tData[index + 1];
  const isMap = tStylingKey === null;
  let cursor = isPrevDir ? getTStylingRangePrev(tStylingAtIndex) : getTStylingRangeNext(tStylingAtIndex);
  let foundDuplicate = false;
  while (cursor !== 0 && (foundDuplicate === false || isMap)) {
    ngDevMode && assertIndexInRange(tData, cursor);
    const tStylingValueAtCursor = tData[cursor];
    const tStyleRangeAtCursor = tData[cursor + 1];
    if (isStylingMatch(tStylingValueAtCursor, tStylingKey)) {
      foundDuplicate = true;
      tData[cursor + 1] = isPrevDir ? setTStylingRangeNextDuplicate(tStyleRangeAtCursor) : setTStylingRangePrevDuplicate(tStyleRangeAtCursor);
    }
    cursor = isPrevDir ? getTStylingRangePrev(tStyleRangeAtCursor) : getTStylingRangeNext(tStyleRangeAtCursor);
  }
  if (foundDuplicate) {
    tData[index + 1] = isPrevDir ? setTStylingRangePrevDuplicate(tStylingAtIndex) : setTStylingRangeNextDuplicate(tStylingAtIndex);
  }
}
function isStylingMatch(tStylingKeyCursor, tStylingKey) {
  ngDevMode && assertNotEqual(Array.isArray(tStylingKey), true, "Expected that 'tStylingKey' has been unwrapped");
  if (tStylingKeyCursor === null || tStylingKey == null || (Array.isArray(tStylingKeyCursor) ? tStylingKeyCursor[1] : tStylingKeyCursor) === tStylingKey) {
    return true;
  } else if (Array.isArray(tStylingKeyCursor) && typeof tStylingKey === 'string') {
    return keyValueArrayIndexOf(tStylingKeyCursor, tStylingKey) >= 0;
  }
  return false;
}

const parserState = {
  textEnd: 0,
  key: 0,
  keyEnd: 0,
  value: 0,
  valueEnd: 0
};
function getLastParsedKey(text) {
  return text.substring(parserState.key, parserState.keyEnd);
}
function getLastParsedValue(text) {
  return text.substring(parserState.value, parserState.valueEnd);
}
function parseClassName(text) {
  resetParserState(text);
  return parseClassNameNext(text, consumeWhitespace(text, 0, parserState.textEnd));
}
function parseClassNameNext(text, index) {
  const end = parserState.textEnd;
  if (end === index) {
    return -1;
  }
  index = parserState.keyEnd = consumeClassToken(text, parserState.key = index, end);
  return consumeWhitespace(text, index, end);
}
function parseStyle(text) {
  resetParserState(text);
  return parseStyleNext(text, consumeWhitespace(text, 0, parserState.textEnd));
}
function parseStyleNext(text, startIndex) {
  const end = parserState.textEnd;
  let index = parserState.key = consumeWhitespace(text, startIndex, end);
  if (end === index) {
    return -1;
  }
  index = parserState.keyEnd = consumeStyleKey(text, index, end);
  index = consumeSeparator(text, index, end, 58);
  index = parserState.value = consumeWhitespace(text, index, end);
  index = parserState.valueEnd = consumeStyleValue(text, index, end);
  return consumeSeparator(text, index, end, 59);
}
function resetParserState(text) {
  parserState.key = 0;
  parserState.keyEnd = 0;
  parserState.value = 0;
  parserState.valueEnd = 0;
  parserState.textEnd = text.length;
}
function consumeWhitespace(text, startIndex, endIndex) {
  while (startIndex < endIndex && text.charCodeAt(startIndex) <= 32) {
    startIndex++;
  }
  return startIndex;
}
function consumeClassToken(text, startIndex, endIndex) {
  while (startIndex < endIndex && text.charCodeAt(startIndex) > 32) {
    startIndex++;
  }
  return startIndex;
}
function consumeStyleKey(text, startIndex, endIndex) {
  let ch;
  while (startIndex < endIndex && ((ch = text.charCodeAt(startIndex)) === 45 || ch === 95 || (ch & -33) >= 65 && (ch & -33) <= 90 || ch >= 48 && ch <= 57)) {
    startIndex++;
  }
  return startIndex;
}
function consumeSeparator(text, startIndex, endIndex, separator) {
  startIndex = consumeWhitespace(text, startIndex, endIndex);
  if (startIndex < endIndex) {
    if (ngDevMode && text.charCodeAt(startIndex) !== separator) {
      malformedStyleError(text, String.fromCharCode(separator), startIndex);
    }
    startIndex++;
  }
  return startIndex;
}
function consumeStyleValue(text, startIndex, endIndex) {
  let ch1 = -1;
  let ch2 = -1;
  let ch3 = -1;
  let i = startIndex;
  let lastChIndex = i;
  while (i < endIndex) {
    const ch = text.charCodeAt(i++);
    if (ch === 59) {
      return lastChIndex;
    } else if (ch === 34 || ch === 39) {
      lastChIndex = i = consumeQuotedText(text, ch, i, endIndex);
    } else if (startIndex === i - 4 && ch3 === 85 && ch2 === 82 && ch1 === 76 && ch === 40) {
      lastChIndex = i = consumeQuotedText(text, 41, i, endIndex);
    } else if (ch > 32) {
      lastChIndex = i;
    }
    ch3 = ch2;
    ch2 = ch1;
    ch1 = ch & -33;
  }
  return lastChIndex;
}
function consumeQuotedText(text, quoteCharCode, startIndex, endIndex) {
  let ch1 = -1;
  let index = startIndex;
  while (index < endIndex) {
    const ch = text.charCodeAt(index++);
    if (ch == quoteCharCode && ch1 !== 92) {
      return index;
    }
    if (ch == 92 && ch1 === 92) {
      ch1 = 0;
    } else {
      ch1 = ch;
    }
  }
  throw ngDevMode ? malformedStyleError(text, String.fromCharCode(quoteCharCode), endIndex) : new Error();
}
function malformedStyleError(text, expecting, index) {
  ngDevMode && assertEqual(typeof text === 'string', true, 'String expected here');
  throw throwError(`Malformed style at location ${index} in string '` + text.substring(0, index) + '[>>' + text.substring(index, index + 1) + '<<]' + text.slice(index + 1) + `'. Expecting '${expecting}'.`);
}

function ɵɵstyleProp(prop, value, suffix) {
  checkStylingProperty(prop, value, suffix, false);
  return ɵɵstyleProp;
}
function ɵɵclassProp(className, value) {
  checkStylingProperty(className, value, null, true);
  return ɵɵclassProp;
}
function ɵɵstyleMap(styles) {
  checkStylingMap(styleKeyValueArraySet, styleStringParser, styles, false);
}
function styleStringParser(keyValueArray, text) {
  for (let i = parseStyle(text); i >= 0; i = parseStyleNext(text, i)) {
    styleKeyValueArraySet(keyValueArray, getLastParsedKey(text), getLastParsedValue(text));
  }
}
function ɵɵclassMap(classes) {
  checkStylingMap(classKeyValueArraySet, classStringParser, classes, true);
}
function classStringParser(keyValueArray, text) {
  for (let i = parseClassName(text); i >= 0; i = parseClassNameNext(text, i)) {
    keyValueArraySet(keyValueArray, getLastParsedKey(text), true);
  }
}
function checkStylingProperty(prop, value, suffix, isClassBased) {
  const lView = getLView();
  const tView = getTView();
  const bindingIndex = incrementBindingIndex(2);
  if (tView.firstUpdatePass) {
    stylingFirstUpdatePass(tView, prop, bindingIndex, isClassBased);
  }
  if (value !== NO_CHANGE && bindingUpdated(lView, bindingIndex, value)) {
    if (ngDevMode && !isClassBased) {
      warnInvalidStylePropValue(prop, value);
    }
    const tNode = tView.data[getSelectedIndex()];
    updateStyling(tView, tNode, lView, lView[RENDERER], prop, lView[bindingIndex + 1] = normalizeSuffix(value, suffix), isClassBased, bindingIndex);
  }
}
function warnInvalidStylePropValue(prop, value) {
  if (value == null || typeof value === 'string' || typeof value === 'number' || getSanitizationBypassType(value) === "Style") {
    return;
  }
  console.warn(formatRuntimeError(-318, `\`[style.${prop}]\` was bound to an invalid value. ` + `Expected a string, number, SafeValue, null, or undefined, but received ` + `\`${typeof value}\` (\`${stringifyInvalidStylePropValue(value)}\`).`));
}
function stringifyInvalidStylePropValue(value) {
  try {
    return stringify(value);
  } catch {
    return '[unstringifiable value]';
  }
}
function checkStylingMap(keyValueArraySet, stringParser, value, isClassBased) {
  const tView = getTView();
  const bindingIndex = incrementBindingIndex(2);
  if (tView.firstUpdatePass) {
    stylingFirstUpdatePass(tView, null, bindingIndex, isClassBased);
  }
  const lView = getLView();
  if (value !== NO_CHANGE && bindingUpdated(lView, bindingIndex, value)) {
    const tNode = tView.data[getSelectedIndex()];
    if (hasStylingInputShadow(tNode, isClassBased) && !isInHostBindings(tView, bindingIndex)) {
      if (ngDevMode) {
        const tStylingKey = tView.data[bindingIndex];
        assertEqual(Array.isArray(tStylingKey) ? tStylingKey[1] : tStylingKey, false, "Styling linked list shadow input should be marked as 'false'");
      }
      let staticPrefix = isClassBased ? tNode.classesWithoutHost : tNode.stylesWithoutHost;
      ngDevMode && isClassBased === false && staticPrefix !== null && assertEqual(staticPrefix.endsWith(';'), true, "Expecting static portion to end with ';'");
      if (staticPrefix !== null) {
        value = concatStringsWithSpace(staticPrefix, value ? value : '');
      }
      setDirectiveInputsWhichShadowsStyling(tView, tNode, lView, value, isClassBased);
    } else {
      updateStylingMap(tView, tNode, lView, lView[RENDERER], lView[bindingIndex + 1], lView[bindingIndex + 1] = toStylingKeyValueArray(keyValueArraySet, stringParser, value), isClassBased, bindingIndex);
    }
  }
}
function isInHostBindings(tView, bindingIndex) {
  return bindingIndex >= tView.expandoStartIndex;
}
function stylingFirstUpdatePass(tView, tStylingKey, bindingIndex, isClassBased) {
  ngDevMode && assertFirstUpdatePass(tView);
  const tData = tView.data;
  if (tData[bindingIndex + 1] === null) {
    const tNode = tData[getSelectedIndex()];
    ngDevMode && assertDefined(tNode, 'TNode expected');
    const isHostBindings = isInHostBindings(tView, bindingIndex);
    if (hasStylingInputShadow(tNode, isClassBased) && tStylingKey === null && !isHostBindings) {
      tStylingKey = false;
    }
    tStylingKey = wrapInStaticStylingKey(tData, tNode, tStylingKey, isClassBased);
    insertTStylingBinding(tData, tNode, tStylingKey, bindingIndex, isHostBindings, isClassBased);
  }
}
function wrapInStaticStylingKey(tData, tNode, stylingKey, isClassBased) {
  const hostDirectiveDef = getCurrentDirectiveDef(tData);
  let residual = isClassBased ? tNode.residualClasses : tNode.residualStyles;
  if (hostDirectiveDef === null) {
    const isFirstStylingInstructionInTemplate = (isClassBased ? tNode.classBindings : tNode.styleBindings) === 0;
    if (isFirstStylingInstructionInTemplate) {
      stylingKey = collectStylingFromDirectives(null, tData, tNode, stylingKey, isClassBased);
      stylingKey = collectStylingFromTAttrs(stylingKey, tNode.attrs, isClassBased);
      residual = null;
    }
  } else {
    const directiveStylingLast = tNode.directiveStylingLast;
    const isFirstStylingInstructionInHostBinding = directiveStylingLast === -1 || tData[directiveStylingLast] !== hostDirectiveDef;
    if (isFirstStylingInstructionInHostBinding) {
      stylingKey = collectStylingFromDirectives(hostDirectiveDef, tData, tNode, stylingKey, isClassBased);
      if (residual === null) {
        let templateStylingKey = getTemplateHeadTStylingKey(tData, tNode, isClassBased);
        if (templateStylingKey !== undefined && Array.isArray(templateStylingKey)) {
          templateStylingKey = collectStylingFromDirectives(null, tData, tNode, templateStylingKey[1], isClassBased);
          templateStylingKey = collectStylingFromTAttrs(templateStylingKey, tNode.attrs, isClassBased);
          setTemplateHeadTStylingKey(tData, tNode, isClassBased, templateStylingKey);
        }
      } else {
        residual = collectResidual(tData, tNode, isClassBased);
      }
    }
  }
  if (residual !== undefined) {
    isClassBased ? tNode.residualClasses = residual : tNode.residualStyles = residual;
  }
  return stylingKey;
}
function getTemplateHeadTStylingKey(tData, tNode, isClassBased) {
  const bindings = isClassBased ? tNode.classBindings : tNode.styleBindings;
  if (getTStylingRangeNext(bindings) === 0) {
    return undefined;
  }
  return tData[getTStylingRangePrev(bindings)];
}
function setTemplateHeadTStylingKey(tData, tNode, isClassBased, tStylingKey) {
  const bindings = isClassBased ? tNode.classBindings : tNode.styleBindings;
  ngDevMode && assertNotEqual(getTStylingRangeNext(bindings), 0, 'Expecting to have at least one template styling binding.');
  tData[getTStylingRangePrev(bindings)] = tStylingKey;
}
function collectResidual(tData, tNode, isClassBased) {
  let residual = undefined;
  const directiveEnd = tNode.directiveEnd;
  ngDevMode && assertNotEqual(tNode.directiveStylingLast, -1, 'By the time this function gets called at least one hostBindings-node styling instruction must have executed.');
  for (let i = 1 + tNode.directiveStylingLast; i < directiveEnd; i++) {
    const attrs = tData[i].hostAttrs;
    residual = collectStylingFromTAttrs(residual, attrs, isClassBased);
  }
  return collectStylingFromTAttrs(residual, tNode.attrs, isClassBased);
}
function collectStylingFromDirectives(hostDirectiveDef, tData, tNode, stylingKey, isClassBased) {
  let currentDirective = null;
  const directiveEnd = tNode.directiveEnd;
  let directiveStylingLast = tNode.directiveStylingLast;
  if (directiveStylingLast === -1) {
    directiveStylingLast = tNode.directiveStart;
  } else {
    directiveStylingLast++;
  }
  while (directiveStylingLast < directiveEnd) {
    currentDirective = tData[directiveStylingLast];
    ngDevMode && assertDefined(currentDirective, 'expected to be defined');
    stylingKey = collectStylingFromTAttrs(stylingKey, currentDirective.hostAttrs, isClassBased);
    if (currentDirective === hostDirectiveDef) break;
    directiveStylingLast++;
  }
  if (hostDirectiveDef !== null) {
    tNode.directiveStylingLast = directiveStylingLast;
  }
  return stylingKey;
}
function collectStylingFromTAttrs(stylingKey, attrs, isClassBased) {
  const desiredMarker = isClassBased ? 1 : 2;
  let currentMarker = -1;
  if (attrs !== null) {
    for (let i = 0; i < attrs.length; i++) {
      const item = attrs[i];
      if (typeof item === 'number') {
        currentMarker = item;
      } else {
        if (currentMarker === desiredMarker) {
          if (!Array.isArray(stylingKey)) {
            stylingKey = stylingKey === undefined ? [] : ['', stylingKey];
          }
          keyValueArraySet(stylingKey, item, isClassBased ? true : attrs[++i]);
        }
      }
    }
  }
  return stylingKey === undefined ? null : stylingKey;
}
function toStylingKeyValueArray(keyValueArraySet, stringParser, value) {
  if (value == null || value === '') return EMPTY_ARRAY;
  const styleKeyValueArray = [];
  const unwrappedValue = unwrapSafeValue(value);
  if (Array.isArray(unwrappedValue)) {
    for (let i = 0; i < unwrappedValue.length; i++) {
      keyValueArraySet(styleKeyValueArray, unwrappedValue[i], true);
    }
  } else if (unwrappedValue instanceof Set) {
    for (const current of unwrappedValue) {
      keyValueArraySet(styleKeyValueArray, current, true);
    }
  } else if (typeof unwrappedValue === 'object') {
    for (const key in unwrappedValue) {
      if (Object.hasOwn(unwrappedValue, key)) {
        keyValueArraySet(styleKeyValueArray, key, unwrappedValue[key]);
      }
    }
  } else if (typeof unwrappedValue === 'string') {
    stringParser(styleKeyValueArray, unwrappedValue);
  } else {
    ngDevMode && throwError('Unsupported styling type: ' + typeof unwrappedValue + ' (' + unwrappedValue + ')');
  }
  return styleKeyValueArray;
}
function styleKeyValueArraySet(keyValueArray, key, value) {
  ngDevMode && warnInvalidStylePropValue(key, value);
  keyValueArraySet(keyValueArray, key, unwrapSafeValue(value));
}
function classKeyValueArraySet(keyValueArray, key, value) {
  const stringKey = String(key);
  if (stringKey !== '' && !stringKey.includes(' ')) {
    keyValueArraySet(keyValueArray, stringKey, value);
  }
}
function updateStylingMap(tView, tNode, lView, renderer, oldKeyValueArray, newKeyValueArray, isClassBased, bindingIndex) {
  if (oldKeyValueArray === NO_CHANGE) {
    oldKeyValueArray = EMPTY_ARRAY;
  }
  let oldIndex = 0;
  let newIndex = 0;
  let oldKey = 0 < oldKeyValueArray.length ? oldKeyValueArray[0] : null;
  let newKey = 0 < newKeyValueArray.length ? newKeyValueArray[0] : null;
  while (oldKey !== null || newKey !== null) {
    ngDevMode && assertLessThan(oldIndex, 999, 'Are we stuck in infinite loop?');
    ngDevMode && assertLessThan(newIndex, 999, 'Are we stuck in infinite loop?');
    const oldValue = oldIndex < oldKeyValueArray.length ? oldKeyValueArray[oldIndex + 1] : undefined;
    const newValue = newIndex < newKeyValueArray.length ? newKeyValueArray[newIndex + 1] : undefined;
    let setKey = null;
    let setValue = undefined;
    if (oldKey === newKey) {
      oldIndex += 2;
      newIndex += 2;
      if (oldValue !== newValue) {
        setKey = newKey;
        setValue = newValue;
      }
    } else if (newKey === null || oldKey !== null && oldKey < newKey) {
      oldIndex += 2;
      setKey = oldKey;
    } else {
      ngDevMode && assertDefined(newKey, 'Expecting to have a valid key');
      newIndex += 2;
      setKey = newKey;
      setValue = newValue;
    }
    if (setKey !== null) {
      updateStyling(tView, tNode, lView, renderer, setKey, setValue, isClassBased, bindingIndex);
    }
    oldKey = oldIndex < oldKeyValueArray.length ? oldKeyValueArray[oldIndex] : null;
    newKey = newIndex < newKeyValueArray.length ? newKeyValueArray[newIndex] : null;
  }
}
function updateStyling(tView, tNode, lView, renderer, prop, value, isClassBased, bindingIndex) {
  if (!(tNode.type & 3)) {
    return;
  }
  const tData = tView.data;
  const tRange = tData[bindingIndex + 1];
  const higherPriorityValue = getTStylingRangeNextDuplicate(tRange) ? findStylingValue(tData, tNode, lView, prop, getTStylingRangeNext(tRange), isClassBased) : undefined;
  if (!isStylingValuePresent(higherPriorityValue)) {
    if (!isStylingValuePresent(value)) {
      if (getTStylingRangePrevDuplicate(tRange)) {
        value = findStylingValue(tData, null, lView, prop, bindingIndex, isClassBased);
      }
    }
    const rNode = getNativeByIndex(getSelectedIndex(), lView);
    applyStyling(renderer, isClassBased, rNode, prop, value);
  }
}
function findStylingValue(tData, tNode, lView, prop, index, isClassBased) {
  const isPrevDirection = tNode === null;
  let value = undefined;
  while (index > 0) {
    const rawKey = tData[index];
    const containsStatics = Array.isArray(rawKey);
    const key = containsStatics ? rawKey[1] : rawKey;
    const isStylingMap = key === null;
    let valueAtLViewIndex = lView[index + 1];
    if (valueAtLViewIndex === NO_CHANGE) {
      valueAtLViewIndex = isStylingMap ? EMPTY_ARRAY : undefined;
    }
    let currentValue = isStylingMap ? keyValueArrayGet(valueAtLViewIndex, prop) : key === prop ? valueAtLViewIndex : undefined;
    if (containsStatics && !isStylingValuePresent(currentValue)) {
      currentValue = keyValueArrayGet(rawKey, prop);
    }
    if (isStylingValuePresent(currentValue)) {
      value = currentValue;
      if (isPrevDirection) {
        return value;
      }
    }
    const tRange = tData[index + 1];
    index = isPrevDirection ? getTStylingRangePrev(tRange) : getTStylingRangeNext(tRange);
  }
  if (tNode !== null) {
    let residual = isClassBased ? tNode.residualClasses : tNode.residualStyles;
    if (residual != null) {
      value = keyValueArrayGet(residual, prop);
    }
  }
  return value;
}
function isStylingValuePresent(value) {
  return value !== undefined;
}
function normalizeSuffix(value, suffix) {
  if (value == null || value === '') ; else if (typeof suffix === 'string') {
    value = unwrapSafeValue(value) + suffix;
  } else if (typeof value === 'object') {
    value = stringify(unwrapSafeValue(value));
  }
  return value;
}
function hasStylingInputShadow(tNode, isClassBased) {
  return (tNode.flags & (isClassBased ? 8 : 16)) !== 0;
}

function ɵɵtext(index, value = '') {
  const lView = getLView();
  const tView = getTView();
  const adjustedIndex = index + HEADER_OFFSET;
  ngDevMode && assertTNodeCreationIndex(lView, index);
  const tNode = tView.firstCreatePass ? getOrCreateTNode(tView, adjustedIndex, 1, value, null) : tView.data[adjustedIndex];
  const textNative = _locateOrCreateTextNode(tView, lView, tNode, value);
  lView[adjustedIndex] = textNative;
  if (wasLastNodeCreated()) {
    appendChild(tView, lView, textNative, tNode);
  }
  setCurrentTNode(tNode, false);
}
let _locateOrCreateTextNode = (tView, lView, tNode, value) => {
  lastNodeWasCreated(true);
  return createTextNode(lView[RENDERER], value);
};
function locateOrCreateTextNodeImpl(tView, lView, tNode, value) {
  const isNodeCreationMode = !canHydrateNode(lView, tNode);
  lastNodeWasCreated(isNodeCreationMode);
  if (isNodeCreationMode) {
    return createTextNode(lView[RENDERER], value);
  }
  const hydrationInfo = lView[HYDRATION];
  const textNative = locateNextRNode(hydrationInfo, tView, lView, tNode);
  ngDevMode && validateMatchingNode(textNative, Node.TEXT_NODE, null, lView, tNode);
  ngDevMode && markRNodeAsClaimedByHydration(textNative);
  return textNative;
}
function enableLocateOrCreateTextNodeImpl() {
  _locateOrCreateTextNode = locateOrCreateTextNodeImpl;
}

function interpolationV(lView, values) {
  ngDevMode && assertLessThan(2, values.length, 'should have at least 3 values');
  let isBindingUpdated = false;
  let bindingIndex = getBindingIndex();
  for (let i = 1; i < values.length; i += 2) {
    isBindingUpdated = bindingUpdated(lView, bindingIndex++, values[i]) || isBindingUpdated;
  }
  setBindingIndex(bindingIndex);
  if (!isBindingUpdated) {
    return NO_CHANGE;
  }
  let content = values[0];
  for (let i = 1; i < values.length; i += 2) {
    content += renderStringify(values[i]) + (i + 1 !== values.length ? values[i + 1] : '');
  }
  return content;
}
function interpolation1(lView, prefix, v0, suffix = '') {
  const different = bindingUpdated(lView, nextBindingIndex(), v0);
  return different ? prefix + renderStringify(v0) + suffix : NO_CHANGE;
}
function interpolation2(lView, prefix, v0, i0, v1, suffix = '') {
  const bindingIndex = getBindingIndex();
  const different = bindingUpdated2(lView, bindingIndex, v0, v1);
  incrementBindingIndex(2);
  return different ? prefix + renderStringify(v0) + i0 + renderStringify(v1) + suffix : NO_CHANGE;
}
function interpolation3(lView, prefix, v0, i0, v1, i1, v2, suffix = '') {
  const bindingIndex = getBindingIndex();
  const different = bindingUpdated3(lView, bindingIndex, v0, v1, v2);
  incrementBindingIndex(3);
  return different ? prefix + renderStringify(v0) + i0 + renderStringify(v1) + i1 + renderStringify(v2) + suffix : NO_CHANGE;
}
function interpolation4(lView, prefix, v0, i0, v1, i1, v2, i2, v3, suffix = '') {
  const bindingIndex = getBindingIndex();
  const different = bindingUpdated4(lView, bindingIndex, v0, v1, v2, v3);
  incrementBindingIndex(4);
  return different ? prefix + renderStringify(v0) + i0 + renderStringify(v1) + i1 + renderStringify(v2) + i2 + renderStringify(v3) + suffix : NO_CHANGE;
}
function interpolation5(lView, prefix, v0, i0, v1, i1, v2, i2, v3, i3, v4, suffix = '') {
  const bindingIndex = getBindingIndex();
  let different = bindingUpdated4(lView, bindingIndex, v0, v1, v2, v3);
  different = bindingUpdated(lView, bindingIndex + 4, v4) || different;
  incrementBindingIndex(5);
  return different ? prefix + renderStringify(v0) + i0 + renderStringify(v1) + i1 + renderStringify(v2) + i2 + renderStringify(v3) + i3 + renderStringify(v4) + suffix : NO_CHANGE;
}
function interpolation6(lView, prefix, v0, i0, v1, i1, v2, i2, v3, i3, v4, i4, v5, suffix = '') {
  const bindingIndex = getBindingIndex();
  let different = bindingUpdated4(lView, bindingIndex, v0, v1, v2, v3);
  different = bindingUpdated2(lView, bindingIndex + 4, v4, v5) || different;
  incrementBindingIndex(6);
  return different ? prefix + renderStringify(v0) + i0 + renderStringify(v1) + i1 + renderStringify(v2) + i2 + renderStringify(v3) + i3 + renderStringify(v4) + i4 + renderStringify(v5) + suffix : NO_CHANGE;
}
function interpolation7(lView, prefix, v0, i0, v1, i1, v2, i2, v3, i3, v4, i4, v5, i5, v6, suffix = '') {
  const bindingIndex = getBindingIndex();
  let different = bindingUpdated4(lView, bindingIndex, v0, v1, v2, v3);
  different = bindingUpdated3(lView, bindingIndex + 4, v4, v5, v6) || different;
  incrementBindingIndex(7);
  return different ? prefix + renderStringify(v0) + i0 + renderStringify(v1) + i1 + renderStringify(v2) + i2 + renderStringify(v3) + i3 + renderStringify(v4) + i4 + renderStringify(v5) + i5 + renderStringify(v6) + suffix : NO_CHANGE;
}
function interpolation8(lView, prefix, v0, i0, v1, i1, v2, i2, v3, i3, v4, i4, v5, i5, v6, i6, v7, suffix = '') {
  const bindingIndex = getBindingIndex();
  let different = bindingUpdated4(lView, bindingIndex, v0, v1, v2, v3);
  different = bindingUpdated4(lView, bindingIndex + 4, v4, v5, v6, v7) || different;
  incrementBindingIndex(8);
  return different ? prefix + renderStringify(v0) + i0 + renderStringify(v1) + i1 + renderStringify(v2) + i2 + renderStringify(v3) + i3 + renderStringify(v4) + i4 + renderStringify(v5) + i5 + renderStringify(v6) + i6 + renderStringify(v7) + suffix : NO_CHANGE;
}

function ɵɵtextInterpolate(v0) {
  ɵɵtextInterpolate1('', v0);
  return ɵɵtextInterpolate;
}
function ɵɵtextInterpolate1(prefix, v0, suffix) {
  const lView = getLView();
  const interpolated = interpolation1(lView, prefix, v0, suffix);
  if (interpolated !== NO_CHANGE) {
    textBindingInternal(lView, getSelectedIndex(), interpolated);
  }
  return ɵɵtextInterpolate1;
}
function ɵɵtextInterpolate2(prefix, v0, i0, v1, suffix) {
  const lView = getLView();
  const interpolated = interpolation2(lView, prefix, v0, i0, v1, suffix);
  if (interpolated !== NO_CHANGE) {
    textBindingInternal(lView, getSelectedIndex(), interpolated);
  }
  return ɵɵtextInterpolate2;
}
function ɵɵtextInterpolate3(prefix, v0, i0, v1, i1, v2, suffix) {
  const lView = getLView();
  const interpolated = interpolation3(lView, prefix, v0, i0, v1, i1, v2, suffix);
  if (interpolated !== NO_CHANGE) {
    textBindingInternal(lView, getSelectedIndex(), interpolated);
  }
  return ɵɵtextInterpolate3;
}
function ɵɵtextInterpolate4(prefix, v0, i0, v1, i1, v2, i2, v3, suffix) {
  const lView = getLView();
  const interpolated = interpolation4(lView, prefix, v0, i0, v1, i1, v2, i2, v3, suffix);
  if (interpolated !== NO_CHANGE) {
    textBindingInternal(lView, getSelectedIndex(), interpolated);
  }
  return ɵɵtextInterpolate4;
}
function ɵɵtextInterpolate5(prefix, v0, i0, v1, i1, v2, i2, v3, i3, v4, suffix) {
  const lView = getLView();
  const interpolated = interpolation5(lView, prefix, v0, i0, v1, i1, v2, i2, v3, i3, v4, suffix);
  if (interpolated !== NO_CHANGE) {
    textBindingInternal(lView, getSelectedIndex(), interpolated);
  }
  return ɵɵtextInterpolate5;
}
function ɵɵtextInterpolate6(prefix, v0, i0, v1, i1, v2, i2, v3, i3, v4, i4, v5, suffix) {
  const lView = getLView();
  const interpolated = interpolation6(lView, prefix, v0, i0, v1, i1, v2, i2, v3, i3, v4, i4, v5, suffix);
  if (interpolated !== NO_CHANGE) {
    textBindingInternal(lView, getSelectedIndex(), interpolated);
  }
  return ɵɵtextInterpolate6;
}
function ɵɵtextInterpolate7(prefix, v0, i0, v1, i1, v2, i2, v3, i3, v4, i4, v5, i5, v6, suffix) {
  const lView = getLView();
  const interpolated = interpolation7(lView, prefix, v0, i0, v1, i1, v2, i2, v3, i3, v4, i4, v5, i5, v6, suffix);
  if (interpolated !== NO_CHANGE) {
    textBindingInternal(lView, getSelectedIndex(), interpolated);
  }
  return ɵɵtextInterpolate7;
}
function ɵɵtextInterpolate8(prefix, v0, i0, v1, i1, v2, i2, v3, i3, v4, i4, v5, i5, v6, i6, v7, suffix) {
  const lView = getLView();
  const interpolated = interpolation8(lView, prefix, v0, i0, v1, i1, v2, i2, v3, i3, v4, i4, v5, i5, v6, i6, v7, suffix);
  if (interpolated !== NO_CHANGE) {
    textBindingInternal(lView, getSelectedIndex(), interpolated);
  }
  return ɵɵtextInterpolate8;
}
function ɵɵtextInterpolateV(values) {
  const lView = getLView();
  const interpolated = interpolationV(lView, values);
  if (interpolated !== NO_CHANGE) {
    textBindingInternal(lView, getSelectedIndex(), interpolated);
  }
  return ɵɵtextInterpolateV;
}
function textBindingInternal(lView, index, value) {
  ngDevMode && assertString(value, 'Value should be a string');
  ngDevMode && assertNotSame(value, NO_CHANGE, 'value should not be NO_CHANGE');
  ngDevMode && assertIndexInRange(lView, index);
  const element = getNativeByIndex(index, lView);
  ngDevMode && assertDefined(element, 'native element should exist');
  updateTextNode(lView[RENDERER], element, value);
}

function ɵɵtwoWayProperty(propName, value, sanitizer) {
  if (isWritableSignal(value)) {
    value = value();
  }
  const lView = getLView();
  const bindingIndex = nextBindingIndex();
  if (bindingUpdated(lView, bindingIndex, value)) {
    const tView = getTView();
    const tNode = getSelectedTNode();
    setPropertyAndInputs(tNode, lView, propName, value, lView[RENDERER], sanitizer);
    ngDevMode && storePropertyBindingMetadata(tView.data, tNode, propName, bindingIndex);
  }
  return ɵɵtwoWayProperty;
}
function ɵɵtwoWayBindingSet(target, value) {
  const canWrite = isWritableSignal(target);
  canWrite && target.set(value);
  return canWrite;
}
function ɵɵtwoWayListener(eventName, listenerFn) {
  const lView = getLView();
  const tView = getTView();
  const tNode = getCurrentTNode();
  listenerInternal(tView, lView, lView[RENDERER], tNode, eventName, listenerFn);
  return ɵɵtwoWayListener;
}

const UNINITIALIZED_LET = {};
function ɵɵdeclareLet(index) {
  performanceMarkFeature('NgLet');
  const tView = getTView();
  const lView = getLView();
  const adjustedIndex = index + HEADER_OFFSET;
  const tNode = getOrCreateTNode(tView, adjustedIndex, 128, null, null);
  setCurrentTNode(tNode, false);
  store(tView, lView, adjustedIndex, UNINITIALIZED_LET);
  return ɵɵdeclareLet;
}
function ɵɵstoreLet(value) {
  const tView = getTView();
  const lView = getLView();
  const index = getSelectedIndex();
  store(tView, lView, index, value);
  return value;
}
function ɵɵreadContextLet(index) {
  const contextLView = getContextLView();
  const value = load(contextLView, HEADER_OFFSET + index);
  if (value === UNINITIALIZED_LET) {
    throw new RuntimeError(314, ngDevMode && 'Attempting to access a @let declaration whose value is not available yet');
  }
  return value;
}

function ɵɵattachSourceLocations(templatePath, locations) {
  const tView = getTView();
  const lView = getLView();
  const renderer = lView[RENDERER];
  const attributeName = 'data-ng-source-location';
  for (const [index, offset, line, column] of locations) {
    const tNode = getTNode(tView, index + HEADER_OFFSET);
    ngDevMode && assertTNodeType(tNode, 2);
    const node = getNativeByIndex(index + HEADER_OFFSET, lView);
    if (!node.hasAttribute(attributeName)) {
      const attributeValue = `${templatePath}@o:${offset},l:${line},c:${column}`;
      renderer.setAttribute(node, attributeName, attributeValue);
    }
  }
}

function ɵɵinterpolate(v0) {
  return bindingUpdated(getLView(), nextBindingIndex(), v0) ? renderStringify(v0) : NO_CHANGE;
}
function ɵɵinterpolate1(prefix, v0, suffix = '') {
  return interpolation1(getLView(), prefix, v0, suffix);
}
function ɵɵinterpolate2(prefix, v0, i0, v1, suffix = '') {
  return interpolation2(getLView(), prefix, v0, i0, v1, suffix);
}
function ɵɵinterpolate3(prefix, v0, i0, v1, i1, v2, suffix = '') {
  return interpolation3(getLView(), prefix, v0, i0, v1, i1, v2, suffix);
}
function ɵɵinterpolate4(prefix, v0, i0, v1, i1, v2, i2, v3, suffix = '') {
  return interpolation4(getLView(), prefix, v0, i0, v1, i1, v2, i2, v3, suffix);
}
function ɵɵinterpolate5(prefix, v0, i0, v1, i1, v2, i2, v3, i3, v4, suffix = '') {
  return interpolation5(getLView(), prefix, v0, i0, v1, i1, v2, i2, v3, i3, v4, suffix);
}
function ɵɵinterpolate6(prefix, v0, i0, v1, i1, v2, i2, v3, i3, v4, i4, v5, suffix = '') {
  return interpolation6(getLView(), prefix, v0, i0, v1, i1, v2, i2, v3, i3, v4, i4, v5, suffix);
}
function ɵɵinterpolate7(prefix, v0, i0, v1, i1, v2, i2, v3, i3, v4, i4, v5, i5, v6, suffix = '') {
  return interpolation7(getLView(), prefix, v0, i0, v1, i1, v2, i2, v3, i3, v4, i4, v5, i5, v6, suffix);
}
function ɵɵinterpolate8(prefix, v0, i0, v1, i1, v2, i2, v3, i3, v4, i4, v5, i5, v6, i6, v7, suffix = '') {
  return interpolation8(getLView(), prefix, v0, i0, v1, i1, v2, i2, v3, i3, v4, i4, v5, i5, v6, i6, v7, suffix);
}
function ɵɵinterpolateV(values) {
  return interpolationV(getLView(), values);
}

function ɵɵarrowFunction(slotOffset, factory, context) {
  const bindingIndex = getBindingRoot() + slotOffset;
  const lView = getLView();
  return lView[bindingIndex] === NO_CHANGE ? updateBinding(lView, bindingIndex, factory(context, lView)) : getBinding(lView, bindingIndex);
}

function providersResolver(def, providers, isViewProviders) {
  const tView = getTView();
  if (tView.firstCreatePass) {
    resolveProvider(providers, tView.data, tView.blueprint, isComponentDef(def), isViewProviders);
  }
}
function resolveProvider(provider, tInjectables, lInjectablesBlueprint, isComponent, isViewProvider) {
  provider = resolveForwardRef(provider);
  if (Array.isArray(provider)) {
    for (let i = 0; i < provider.length; i++) {
      resolveProvider(provider[i], tInjectables, lInjectablesBlueprint, isComponent, isViewProvider);
    }
  } else {
    const tView = getTView();
    const lView = getLView();
    const tNode = getCurrentTNode();
    let token = isTypeProvider(provider) ? provider : resolveForwardRef(provider.provide);
    const providerFactory = providerToFactory(provider);
    if (ngDevMode) {
      const injector = new NodeInjector(tNode, lView);
      runInInjectorProfilerContext(injector, token, () => {
        emitProviderConfiguredEvent(provider, isViewProvider);
      });
    }
    const beginIndex = tNode.providerIndexes & 1048575;
    const endIndex = tNode.directiveStart;
    const cptViewProvidersCount = tNode.providerIndexes >> 20;
    if (isTypeProvider(provider) || !provider.multi) {
      const factory = new NodeInjectorFactory(providerFactory, isViewProvider, ɵɵdirectiveInject, ngDevMode ? providerName(provider) : null);
      const existingFactoryIndex = indexOf(token, tInjectables, isViewProvider ? beginIndex : beginIndex + cptViewProvidersCount, endIndex);
      if (existingFactoryIndex === -1) {
        diPublicInInjector(getOrCreateNodeInjectorForNode(tNode, lView), tView, token);
        registerDestroyHooksIfSupported(tView, provider, tInjectables.length);
        tInjectables.push(token);
        tNode.directiveStart++;
        tNode.directiveEnd++;
        if (isViewProvider) {
          tNode.providerIndexes += 1048576;
        }
        lInjectablesBlueprint.push(factory);
        lView.push(factory);
      } else {
        lInjectablesBlueprint[existingFactoryIndex] = factory;
        lView[existingFactoryIndex] = factory;
      }
    } else {
      const existingProvidersFactoryIndex = indexOf(token, tInjectables, beginIndex + cptViewProvidersCount, endIndex);
      const existingViewProvidersFactoryIndex = indexOf(token, tInjectables, beginIndex, beginIndex + cptViewProvidersCount);
      const doesProvidersFactoryExist = existingProvidersFactoryIndex >= 0 && lInjectablesBlueprint[existingProvidersFactoryIndex];
      const doesViewProvidersFactoryExist = existingViewProvidersFactoryIndex >= 0 && lInjectablesBlueprint[existingViewProvidersFactoryIndex];
      if (isViewProvider && !doesViewProvidersFactoryExist || !isViewProvider && !doesProvidersFactoryExist) {
        diPublicInInjector(getOrCreateNodeInjectorForNode(tNode, lView), tView, token);
        const factory = multiFactory(isViewProvider ? multiViewProvidersFactoryResolver : multiProvidersFactoryResolver, lInjectablesBlueprint.length, isViewProvider, isComponent, providerFactory, provider);
        if (!isViewProvider && doesViewProvidersFactoryExist) {
          lInjectablesBlueprint[existingViewProvidersFactoryIndex].providerFactory = factory;
        }
        registerDestroyHooksIfSupported(tView, provider, tInjectables.length, 0);
        tInjectables.push(token);
        tNode.directiveStart++;
        tNode.directiveEnd++;
        if (isViewProvider) {
          tNode.providerIndexes += 1048576;
        }
        lInjectablesBlueprint.push(factory);
        lView.push(factory);
      } else {
        const indexInFactory = multiFactoryAdd(lInjectablesBlueprint[isViewProvider ? existingViewProvidersFactoryIndex : existingProvidersFactoryIndex], providerFactory, !isViewProvider && isComponent);
        registerDestroyHooksIfSupported(tView, provider, existingProvidersFactoryIndex > -1 ? existingProvidersFactoryIndex : existingViewProvidersFactoryIndex, indexInFactory);
      }
      if (!isViewProvider && isComponent && doesViewProvidersFactoryExist) {
        lInjectablesBlueprint[existingViewProvidersFactoryIndex].componentProviders++;
      }
    }
  }
}
function registerDestroyHooksIfSupported(tView, provider, contextIndex, indexInFactory) {
  const providerIsTypeProvider = isTypeProvider(provider);
  const providerIsClassProvider = isClassProvider(provider);
  if (providerIsTypeProvider || providerIsClassProvider) {
    const classToken = providerIsClassProvider ? resolveForwardRef(provider.useClass) : provider;
    const prototype = classToken.prototype;
    const ngOnDestroy = prototype.ngOnDestroy;
    if (ngOnDestroy) {
      const hooks = tView.destroyHooks || (tView.destroyHooks = []);
      if (!providerIsTypeProvider && provider.multi) {
        ngDevMode && assertDefined(indexInFactory, 'indexInFactory when registering multi factory destroy hook');
        const existingCallbacksIndex = hooks.indexOf(contextIndex);
        if (existingCallbacksIndex === -1) {
          hooks.push(contextIndex, [indexInFactory, ngOnDestroy]);
        } else {
          hooks[existingCallbacksIndex + 1].push(indexInFactory, ngOnDestroy);
        }
      } else {
        hooks.push(contextIndex, ngOnDestroy);
      }
    }
  }
}
function multiFactoryAdd(multiFactory, factory, isComponentProvider) {
  if (isComponentProvider) {
    multiFactory.componentProviders++;
  }
  return multiFactory.multi.push(factory) - 1;
}
function indexOf(item, arr, begin, end) {
  for (let i = begin; i < end; i++) {
    if (arr[i] === item) return i;
  }
  return -1;
}
function multiProvidersFactoryResolver(_, flags, tData, lData, tNode) {
  return multiResolve(this.multi, []);
}
function multiViewProvidersFactoryResolver(_, _flags, _tData, lView, tNode) {
  const factories = this.multi;
  let result;
  if (this.providerFactory) {
    const componentCount = this.providerFactory.componentProviders;
    const multiProviders = getNodeInjectable(lView, lView[TVIEW$1], this.providerFactory.index, tNode);
    result = multiProviders.slice(0, componentCount);
    multiResolve(factories, result);
    for (let i = componentCount; i < multiProviders.length; i++) {
      result.push(multiProviders[i]);
    }
  } else {
    result = [];
    multiResolve(factories, result);
  }
  return result;
}
function multiResolve(factories, result) {
  for (let i = 0; i < factories.length; i++) {
    const factory = factories[i];
    result.push(factory());
  }
  return result;
}
function multiFactory(factoryFn, index, isViewProvider, isComponent, f, provider) {
  const factory = new NodeInjectorFactory(factoryFn, isViewProvider, ɵɵdirectiveInject, ngDevMode ? providerName(provider) : null);
  factory.multi = [];
  factory.index = index;
  factory.componentProviders = 0;
  multiFactoryAdd(factory, f, isComponent && !isViewProvider);
  return factory;
}
function providerName(provider) {
  if (Array.isArray(provider)) {
    return null;
  }
  if (isTypeProvider(provider)) {
    return provider.name;
  } else if (isClassProvider(provider)) {
    if (provider.provide instanceof InjectionToken) {
      return `('${provider.provide.toString()}':${provider.useClass.name})`;
    }
    return provider.useClass.name;
  } else if (provider.provide instanceof InjectionToken) {
    return provider.provide.toString();
  } else if (typeof provider.provide === 'string') {
    return provider.provide;
  } else {
    return null;
  }
}

function ɵɵProvidersFeature(providers, viewProviders) {
  return definition => {
    definition.providersResolver = (def, processProvidersFn) => providersResolver(def, processProvidersFn ? processProvidersFn(providers) : providers, false);
    if (viewProviders) {
      definition.viewProvidersResolver = (def, processProvidersFn) => providersResolver(def, processProvidersFn ? processProvidersFn(viewProviders) : viewProviders, true);
    }
  };
}

function ɵɵExternalStylesFeature(styleUrls) {
  return definition => {
    if (styleUrls.length < 1) {
      return;
    }
    definition.getExternalStyles = encapsulationId => {
      const urls = styleUrls.map(value => value + '?ngcomp' + (encapsulationId ? '=' + encodeURIComponent(encapsulationId) : '') + '&e=' + definition.encapsulation);
      return urls;
    };
  };
}

function ɵɵsetComponentScope(type, directives, pipes) {
  const def = type.ɵcmp;
  def.directiveDefs = extractDefListOrFactory(directives, extractDirectiveDef);
  def.pipeDefs = extractDefListOrFactory(pipes, getPipeDef$1);
}
function ɵɵsetNgModuleScope(type, scope) {
  return noSideEffects(() => {
    const ngModuleDef = getNgModuleDefOrThrow(type);
    ngModuleDef.declarations = convertToTypeArray(scope.declarations || EMPTY_ARRAY);
    ngModuleDef.imports = convertToTypeArray(scope.imports || EMPTY_ARRAY);
    ngModuleDef.exports = convertToTypeArray(scope.exports || EMPTY_ARRAY);
    if (scope.bootstrap) {
      ngModuleDef.bootstrap = convertToTypeArray(scope.bootstrap);
    }
    depsTracker.registerNgModule(type, scope);
  });
}
function convertToTypeArray(values) {
  if (typeof values === 'function') {
    return values;
  }
  const flattenValues = flatten(values);
  if (flattenValues.some(isForwardRef)) {
    return () => flattenValues.map(resolveForwardRef).map(maybeUnwrapModuleWithProviders);
  } else {
    return flattenValues.map(maybeUnwrapModuleWithProviders);
  }
}
function maybeUnwrapModuleWithProviders(value) {
  return isModuleWithProviders(value) ? value.ngModule : value;
}

let _dehydratedBlockRegistryFactory = () => null;
let _runIncrementalHydrationBootstrap = () => {};
let isIncrementalHydrationRuntimeActive = false;
const INCREMENTAL_HYDRATION_BOOTSTRAP = new InjectionToken(typeof ngDevMode === 'undefined' || ngDevMode ? 'INCREMENTAL_HYDRATION_BOOTSTRAP' : '');
function createDehydratedBlockRegistry() {
  return _dehydratedBlockRegistryFactory();
}
function runIncrementalHydrationBootstrap(state) {
  if (state.requested && state.activated) {
    _runIncrementalHydrationBootstrap(state.injector, state.document);
  }
}
function ɵɵenableIncrementalHydrationRuntime() {
  if (!isIncrementalHydrationRuntimeActive) {
    isIncrementalHydrationRuntimeActive = true;
    enableRetrieveDeferBlockDataImpl();
    performanceMarkFeature('NgIncrementalHydration');
    _dehydratedBlockRegistryFactory = () => new DehydratedBlockRegistry();
    _runIncrementalHydrationBootstrap = (injector, doc) => {
      const deferBlockData = processBlockData(injector);
      const commentsByBlockId = gatherDeferBlocksCommentNodes(doc, doc.body);
      processAndInitTriggers(injector, deferBlockData, commentsByBlockId);
      appendDeferBlocksToJSActionMap(doc, injector);
    };
  }
  if (typeof ngServerMode === 'undefined' || !ngServerMode) {
    const injector = getLView()[INJECTOR];
    const state = injector.get(INCREMENTAL_HYDRATION_BOOTSTRAP, null, {
      optional: true
    });
    if (state !== null && !state.activated) {
      state.activated = true;
      runIncrementalHydrationBootstrap(state);
    }
  }
}
function resetIncrementalHydrationRuntimeForTests() {
  isIncrementalHydrationRuntimeActive = false;
  _dehydratedBlockRegistryFactory = () => null;
  _runIncrementalHydrationBootstrap = () => {};
}

function ɵɵpureFunction0(slotOffset, pureFn) {
  const bindingIndex = getBindingRoot() + slotOffset;
  const lView = getLView();
  return lView[bindingIndex] === NO_CHANGE ? updateBinding(lView, bindingIndex, pureFn()) : getBinding(lView, bindingIndex);
}
function ɵɵpureFunction1(slotOffset, pureFn, exp) {
  return pureFunction1Internal(getLView(), getBindingRoot(), slotOffset, pureFn, exp);
}
function ɵɵpureFunction2(slotOffset, pureFn, exp1, exp2) {
  return pureFunction2Internal(getLView(), getBindingRoot(), slotOffset, pureFn, exp1, exp2);
}
function ɵɵpureFunction3(slotOffset, pureFn, exp1, exp2, exp3) {
  return pureFunction3Internal(getLView(), getBindingRoot(), slotOffset, pureFn, exp1, exp2, exp3);
}
function ɵɵpureFunction4(slotOffset, pureFn, exp1, exp2, exp3, exp4, thisArg) {
  return pureFunction4Internal(getLView(), getBindingRoot(), slotOffset, pureFn, exp1, exp2, exp3, exp4);
}
function ɵɵpureFunction5(slotOffset, pureFn, exp1, exp2, exp3, exp4, exp5) {
  const bindingIndex = getBindingRoot() + slotOffset;
  const lView = getLView();
  const different = bindingUpdated4(lView, bindingIndex, exp1, exp2, exp3, exp4);
  return bindingUpdated(lView, bindingIndex + 4, exp5) || different ? updateBinding(lView, bindingIndex + 5, pureFn(exp1, exp2, exp3, exp4, exp5)) : getBinding(lView, bindingIndex + 5);
}
function ɵɵpureFunction6(slotOffset, pureFn, exp1, exp2, exp3, exp4, exp5, exp6) {
  const bindingIndex = getBindingRoot() + slotOffset;
  const lView = getLView();
  const different = bindingUpdated4(lView, bindingIndex, exp1, exp2, exp3, exp4);
  return bindingUpdated2(lView, bindingIndex + 4, exp5, exp6) || different ? updateBinding(lView, bindingIndex + 6, pureFn(exp1, exp2, exp3, exp4, exp5, exp6)) : getBinding(lView, bindingIndex + 6);
}
function ɵɵpureFunction7(slotOffset, pureFn, exp1, exp2, exp3, exp4, exp5, exp6, exp7) {
  const bindingIndex = getBindingRoot() + slotOffset;
  const lView = getLView();
  let different = bindingUpdated4(lView, bindingIndex, exp1, exp2, exp3, exp4);
  return bindingUpdated3(lView, bindingIndex + 4, exp5, exp6, exp7) || different ? updateBinding(lView, bindingIndex + 7, pureFn(exp1, exp2, exp3, exp4, exp5, exp6, exp7)) : getBinding(lView, bindingIndex + 7);
}
function ɵɵpureFunction8(slotOffset, pureFn, exp1, exp2, exp3, exp4, exp5, exp6, exp7, exp8) {
  const bindingIndex = getBindingRoot() + slotOffset;
  const lView = getLView();
  const different = bindingUpdated4(lView, bindingIndex, exp1, exp2, exp3, exp4);
  return bindingUpdated4(lView, bindingIndex + 4, exp5, exp6, exp7, exp8) || different ? updateBinding(lView, bindingIndex + 8, pureFn(exp1, exp2, exp3, exp4, exp5, exp6, exp7, exp8)) : getBinding(lView, bindingIndex + 8);
}
function ɵɵpureFunctionV(slotOffset, pureFn, exps) {
  return pureFunctionVInternal(getLView(), getBindingRoot(), slotOffset, pureFn, exps);
}
function getPureFunctionReturnValue(lView, returnValueIndex) {
  ngDevMode && assertIndexInRange(lView, returnValueIndex);
  const lastReturnValue = lView[returnValueIndex];
  return lastReturnValue === NO_CHANGE ? undefined : lastReturnValue;
}
function pureFunction1Internal(lView, bindingRoot, slotOffset, pureFn, exp, thisArg) {
  const bindingIndex = bindingRoot + slotOffset;
  return bindingUpdated(lView, bindingIndex, exp) ? updateBinding(lView, bindingIndex + 1, thisArg ? pureFn.call(thisArg, exp) : pureFn(exp)) : getPureFunctionReturnValue(lView, bindingIndex + 1);
}
function pureFunction2Internal(lView, bindingRoot, slotOffset, pureFn, exp1, exp2, thisArg) {
  const bindingIndex = bindingRoot + slotOffset;
  return bindingUpdated2(lView, bindingIndex, exp1, exp2) ? updateBinding(lView, bindingIndex + 2, thisArg ? pureFn.call(thisArg, exp1, exp2) : pureFn(exp1, exp2)) : getPureFunctionReturnValue(lView, bindingIndex + 2);
}
function pureFunction3Internal(lView, bindingRoot, slotOffset, pureFn, exp1, exp2, exp3, thisArg) {
  const bindingIndex = bindingRoot + slotOffset;
  return bindingUpdated3(lView, bindingIndex, exp1, exp2, exp3) ? updateBinding(lView, bindingIndex + 3, thisArg ? pureFn.call(thisArg, exp1, exp2, exp3) : pureFn(exp1, exp2, exp3)) : getPureFunctionReturnValue(lView, bindingIndex + 3);
}
function pureFunction4Internal(lView, bindingRoot, slotOffset, pureFn, exp1, exp2, exp3, exp4, thisArg) {
  const bindingIndex = bindingRoot + slotOffset;
  return bindingUpdated4(lView, bindingIndex, exp1, exp2, exp3, exp4) ? updateBinding(lView, bindingIndex + 4, thisArg ? pureFn.call(thisArg, exp1, exp2, exp3, exp4) : pureFn(exp1, exp2, exp3, exp4)) : getPureFunctionReturnValue(lView, bindingIndex + 4);
}
function pureFunctionVInternal(lView, bindingRoot, slotOffset, pureFn, exps, thisArg) {
  let bindingIndex = bindingRoot + slotOffset;
  let different = false;
  for (let i = 0; i < exps.length; i++) {
    bindingUpdated(lView, bindingIndex++, exps[i]) && (different = true);
  }
  return different ? updateBinding(lView, bindingIndex, pureFn.apply(thisArg, exps)) : getPureFunctionReturnValue(lView, bindingIndex);
}

function ɵɵpipe(index, pipeName) {
  const tView = getTView();
  let pipeDef;
  const adjustedIndex = index + HEADER_OFFSET;
  if (tView.firstCreatePass) {
    pipeDef = getPipeDef(pipeName, tView.pipeRegistry);
    tView.data[adjustedIndex] = pipeDef;
    if (pipeDef.onDestroy) {
      (tView.destroyHooks ??= []).push(adjustedIndex, pipeDef.onDestroy);
    }
  } else {
    pipeDef = tView.data[adjustedIndex];
  }
  const pipeFactory = pipeDef.factory || (pipeDef.factory = getFactoryDef(pipeDef.type, true));
  let previousInjectorProfilerContext;
  if (ngDevMode) {
    previousInjectorProfilerContext = setInjectorProfilerContext({
      injector: new NodeInjector(getCurrentTNode(), getLView()),
      token: pipeDef.type
    });
  }
  const previousInjectImplementation = setInjectImplementation(ɵɵdirectiveInject);
  try {
    const previousIncludeViewProviders = setIncludeViewProviders(false);
    const pipeInstance = pipeFactory();
    setIncludeViewProviders(previousIncludeViewProviders);
    store(tView, getLView(), adjustedIndex, pipeInstance);
    return pipeInstance;
  } finally {
    setInjectImplementation(previousInjectImplementation);
    ngDevMode && setInjectorProfilerContext(previousInjectorProfilerContext);
  }
}
function getPipeDef(name, registry) {
  if (registry) {
    if (ngDevMode) {
      const pipes = registry.filter(pipe => pipe.name === name);
      if (pipes.length > 1) {
        console.warn(formatRuntimeError(313, getMultipleMatchingPipesMessage(name)));
      }
    }
    for (let i = registry.length - 1; i >= 0; i--) {
      const pipeDef = registry[i];
      if (name === pipeDef.name) {
        return pipeDef;
      }
    }
  }
  if (ngDevMode) {
    throw new RuntimeError(-302, getPipeNotFoundErrorMessage(name));
  }
  return;
}
function getMultipleMatchingPipesMessage(name) {
  const lView = getLView();
  const declarationLView = lView[DECLARATION_COMPONENT_VIEW];
  const context = declarationLView[CONTEXT];
  const hostIsStandalone = isHostComponentStandalone(lView);
  const componentInfoMessage = context ? ` in the '${context.constructor.name}' component` : '';
  const verifyMessage = `check ${hostIsStandalone ? "'@Component.imports' of this component" : 'the imports of this module'}`;
  const errorMessage = `Multiple pipes match the name \`${name}\`${componentInfoMessage}. ${verifyMessage}`;
  return errorMessage;
}
function getPipeNotFoundErrorMessage(name) {
  const lView = getLView();
  const declarationLView = lView[DECLARATION_COMPONENT_VIEW];
  const context = declarationLView[CONTEXT];
  const hostIsStandalone = isHostComponentStandalone(lView);
  const componentInfoMessage = context ? ` in the '${context.constructor.name}' component` : '';
  const verifyMessage = `Verify that it is ${hostIsStandalone ? "included in the '@Component.imports' of this component" : 'declared or imported in this module'}`;
  const errorMessage = `The pipe '${name}' could not be found${componentInfoMessage}. ${verifyMessage}`;
  return errorMessage;
}
function ɵɵpipeBind1(index, offset, v1) {
  const adjustedIndex = index + HEADER_OFFSET;
  const lView = getLView();
  const pipeInstance = load(lView, adjustedIndex);
  return isPure(lView, adjustedIndex) ? pureFunction1Internal(lView, getBindingRoot(), offset, pipeInstance.transform, v1, pipeInstance) : pipeInstance.transform(v1);
}
function ɵɵpipeBind2(index, slotOffset, v1, v2) {
  const adjustedIndex = index + HEADER_OFFSET;
  const lView = getLView();
  const pipeInstance = load(lView, adjustedIndex);
  return isPure(lView, adjustedIndex) ? pureFunction2Internal(lView, getBindingRoot(), slotOffset, pipeInstance.transform, v1, v2, pipeInstance) : pipeInstance.transform(v1, v2);
}
function ɵɵpipeBind3(index, slotOffset, v1, v2, v3) {
  const adjustedIndex = index + HEADER_OFFSET;
  const lView = getLView();
  const pipeInstance = load(lView, adjustedIndex);
  return isPure(lView, adjustedIndex) ? pureFunction3Internal(lView, getBindingRoot(), slotOffset, pipeInstance.transform, v1, v2, v3, pipeInstance) : pipeInstance.transform(v1, v2, v3);
}
function ɵɵpipeBind4(index, slotOffset, v1, v2, v3, v4) {
  const adjustedIndex = index + HEADER_OFFSET;
  const lView = getLView();
  const pipeInstance = load(lView, adjustedIndex);
  return isPure(lView, adjustedIndex) ? pureFunction4Internal(lView, getBindingRoot(), slotOffset, pipeInstance.transform, v1, v2, v3, v4, pipeInstance) : pipeInstance.transform(v1, v2, v3, v4);
}
function ɵɵpipeBindV(index, slotOffset, values) {
  const adjustedIndex = index + HEADER_OFFSET;
  const lView = getLView();
  const pipeInstance = load(lView, adjustedIndex);
  return isPure(lView, adjustedIndex) ? pureFunctionVInternal(lView, getBindingRoot(), slotOffset, pipeInstance.transform, values, pipeInstance) : pipeInstance.transform.apply(pipeInstance, values);
}
function isPure(lView, index) {
  return lView[TVIEW$1].data[index].pure;
}

function ɵɵtemplateRefExtractor(tNode, lView) {
  return createTemplateRef(tNode, lView);
}

function ɵɵgetComponentDepsFactory(type, rawImports) {
  return () => {
    try {
      return depsTracker.getComponentDependencies(type, rawImports).dependencies;
    } catch (e) {
      console.error(`Computing dependencies in local compilation mode for the component "${type.name}" failed with the exception:`, e);
      throw e;
    }
  };
}

function ɵsetClassDebugInfo(type, debugInfo) {
  const def = getComponentDef(type);
  if (def !== null) {
    def.debugInfo = debugInfo;
  }
}

function ɵɵgetReplaceMetadataURL(id, timestamp, base) {
  const url = `./@ng/component?c=${id}&t=${encodeURIComponent(timestamp)}`;
  return new URL(url, base).href;
}
function ɵɵreplaceMetadata(type, applyMetadata, namespaces, locals, importMeta = null, id = null) {
  ngDevMode && assertComponentDef(type);
  const currentDef = getComponentDef(type);
  applyMetadata.apply(null, [type, namespaces, ...locals]);
  const {
    newDef,
    oldDef
  } = mergeWithExistingDefinition(currentDef, getComponentDef(type));
  type[NG_COMP_DEF] = newDef;
  if (oldDef.tView) {
    const trackedViews = getTrackedLViews().values();
    for (const root of trackedViews) {
      if (isRootView(root) && root[PARENT] === null) {
        recreateMatchingLViews(importMeta, id, newDef, oldDef, root);
      }
    }
  }
}
function mergeWithExistingDefinition(currentDef, newDef) {
  const clone = {
    ...currentDef
  };
  const replacement = Object.assign(currentDef, newDef, {
    directiveDefs: clone.directiveDefs,
    pipeDefs: clone.pipeDefs,
    setInput: clone.setInput,
    type: clone.type
  });
  ngDevMode && assertEqual(replacement, currentDef, 'Expected definition to be merged in place');
  return {
    newDef: replacement,
    oldDef: clone
  };
}
function recreateMatchingLViews(importMeta, id, newDef, oldDef, rootLView) {
  ngDevMode && assertDefined(oldDef.tView, 'Expected a component definition that has been instantiated at least once');
  const tView = rootLView[TVIEW$1];
  if (tView === oldDef.tView) {
    ngDevMode && assertComponentDef(oldDef.type);
    recreateLView(importMeta, id, newDef, oldDef, rootLView);
    return;
  }
  for (let i = HEADER_OFFSET; i < tView.bindingStartIndex; i++) {
    const current = rootLView[i];
    if (isLContainer(current)) {
      if (isLView(current[HOST])) {
        recreateMatchingLViews(importMeta, id, newDef, oldDef, current[HOST]);
      }
      for (let j = CONTAINER_HEADER_OFFSET; j < current.length; j++) {
        recreateMatchingLViews(importMeta, id, newDef, oldDef, current[j]);
      }
    } else if (isLView(current)) {
      recreateMatchingLViews(importMeta, id, newDef, oldDef, current);
    }
  }
}
function clearRendererCache(factory, def) {
  factory.componentReplaced?.(def.id);
}
function recreateLView(importMeta, id, newDef, oldDef, lView) {
  const instance = lView[CONTEXT];
  let host = lView[HOST];
  const parentLView = lView[PARENT];
  ngDevMode && assertLView(parentLView);
  const tNode = lView[T_HOST];
  ngDevMode && assertTNodeType(tNode, 2);
  ngDevMode && assertNotEqual(newDef, oldDef, 'Expected different component definition');
  const zone = lView[INJECTOR].get(NgZone, null);
  const recreate = () => {
    if (oldDef.encapsulation === ViewEncapsulation.ShadowDom || oldDef.encapsulation === ViewEncapsulation.ExperimentalIsolatedShadowDom) {
      const newHost = host.cloneNode(false);
      host.replaceWith(newHost);
      host = newHost;
    }
    const newTView = getOrCreateComponentTView(newDef);
    const newLView = createLView(parentLView, newTView, instance, getInitialLViewFlagsFromDef(newDef), host, tNode, null, null, null, null, null);
    replaceLViewInTree(parentLView, lView, newLView, tNode.index);
    destroyLView(lView[TVIEW$1], lView);
    cleanupLView(lView);
    const rendererFactory = lView[ENVIRONMENT].rendererFactory;
    clearRendererCache(rendererFactory, oldDef);
    newLView[RENDERER] = rendererFactory.createRenderer(host, newDef);
    removeViewFromDOM(lView[TVIEW$1], lView);
    resetProjectionState(tNode);
    renderView(newTView, newLView, instance);
    newLView[FLAGS] &= -1025;
    refreshView(newTView, newLView, newTView.template, instance);
  };
  if (zone === null) {
    executeWithInvalidateFallback(importMeta, id, recreate);
  } else {
    zone.run(() => executeWithInvalidateFallback(importMeta, id, recreate));
  }
}
function executeWithInvalidateFallback(importMeta, id, callback) {
  try {
    callback();
  } catch (e) {
    const error = e;
    if (id !== null && error.message) {
      const toLog = error.message + (error.stack ? '\n' + error.stack : '');
      importMeta?.hot?.send?.('angular:invalidate', {
        id,
        message: toLog,
        error: true
      });
    }
    throw e;
  }
}
function replaceLViewInTree(parentLView, oldLView, newLView, index) {
  for (let i = HEADER_OFFSET; i < parentLView[TVIEW$1].bindingStartIndex; i++) {
    const current = parentLView[i];
    if ((isLView(current) || isLContainer(current)) && current[NEXT] === oldLView) {
      current[NEXT] = newLView;
      break;
    }
  }
  if (parentLView[CHILD_HEAD] === oldLView) {
    parentLView[CHILD_HEAD] = newLView;
  }
  if (parentLView[CHILD_TAIL] === oldLView) {
    parentLView[CHILD_TAIL] = newLView;
  }
  newLView[NEXT] = oldLView[NEXT];
  oldLView[NEXT] = null;
  parentLView[index] = newLView;
}
function resetProjectionState(tNode) {
  if (tNode.projection !== null) {
    for (const current of tNode.projection) {
      if (isTNodeShape(current)) {
        current.projectionNext = null;
        current.flags &= -3;
      }
    }
    tNode.projection = null;
  }
}

const angularCoreEnv = (() => ({
  'ɵɵanimateEnter': ɵɵanimateEnter,
  'ɵɵanimateEnterListener': ɵɵanimateEnterListener,
  'ɵɵanimateLeave': ɵɵanimateLeave,
  'ɵɵanimateLeaveListener': ɵɵanimateLeaveListener,
  'ɵɵattribute': ɵɵattribute,
  'ɵɵdefineComponent': ɵɵdefineComponent,
  'ɵɵdefineDirective': ɵɵdefineDirective,
  'ɵɵdefineInjectable': __defineInjectable,
  'ɵɵdefineInjector': __defineInjector,
  'ɵɵdefineNgModule': ɵɵdefineNgModule,
  'ɵɵdefineService': ɵɵdefineService,
  'ɵɵdefinePipe': ɵɵdefinePipe,
  'ɵɵdirectiveInject': ɵɵdirectiveInject,
  'ɵɵgetInheritedFactory': ɵɵgetInheritedFactory,
  'ɵɵinject': __inject,
  'ɵɵinjectAttribute': ɵɵinjectAttribute,
  'ɵɵinvalidFactory': ɵɵinvalidFactory,
  'ɵɵinvalidFactoryDep': __invalidFactoryDep,
  'ɵɵtemplateRefExtractor': ɵɵtemplateRefExtractor,
  'ɵɵresetView': __resetView,
  'ɵɵHostDirectivesFeature': ɵɵHostDirectivesFeature,
  'ɵɵNgOnChangesFeature': ɵɵNgOnChangesFeature,
  'ɵɵControlFeature': ɵɵControlFeature,
  'ɵɵProvidersFeature': ɵɵProvidersFeature,
  'ɵɵInheritDefinitionFeature': ɵɵInheritDefinitionFeature,
  'ɵɵExternalStylesFeature': ɵɵExternalStylesFeature,
  'ɵɵnextContext': ɵɵnextContext,
  'ɵɵnamespaceHTML': __namespaceHTML,
  'ɵɵnamespaceMathML': __namespaceMathML,
  'ɵɵnamespaceSVG': __namespaceSVG,
  'ɵɵenableBindings': __enableBindings,
  'ɵɵdisableBindings': __disableBindings,
  'ɵɵelementStart': ɵɵelementStart,
  'ɵɵelementEnd': ɵɵelementEnd,
  'ɵɵelement': ɵɵelement,
  'ɵɵforeignComponent': ɵɵforeignComponent,
  'ɵɵforeignContent': ɵɵforeignContent,
  'ɵɵforeignContentFn': ɵɵforeignContentFn,
  'ɵɵelementContainerStart': ɵɵelementContainerStart,
  'ɵɵelementContainerEnd': ɵɵelementContainerEnd,
  'ɵɵdomElement': ɵɵdomElement,
  'ɵɵdomElementStart': ɵɵdomElementStart,
  'ɵɵdomElementEnd': ɵɵdomElementEnd,
  'ɵɵdomElementContainer': ɵɵdomElementContainer,
  'ɵɵdomElementContainerStart': ɵɵdomElementContainerStart,
  'ɵɵdomElementContainerEnd': ɵɵdomElementContainerEnd,
  'ɵɵdomTemplate': ɵɵdomTemplate,
  'ɵɵdomListener': ɵɵdomListener,
  'ɵɵelementContainer': ɵɵelementContainer,
  'ɵɵpureFunction0': ɵɵpureFunction0,
  'ɵɵpureFunction1': ɵɵpureFunction1,
  'ɵɵpureFunction2': ɵɵpureFunction2,
  'ɵɵpureFunction3': ɵɵpureFunction3,
  'ɵɵpureFunction4': ɵɵpureFunction4,
  'ɵɵpureFunction5': ɵɵpureFunction5,
  'ɵɵpureFunction6': ɵɵpureFunction6,
  'ɵɵpureFunction7': ɵɵpureFunction7,
  'ɵɵpureFunction8': ɵɵpureFunction8,
  'ɵɵpureFunctionV': ɵɵpureFunctionV,
  'ɵɵgetCurrentView': ɵɵgetCurrentView,
  'ɵɵrestoreView': __restoreView,
  'ɵɵlistener': ɵɵlistener,
  'ɵɵprojection': ɵɵprojection,
  'ɵɵsyntheticHostProperty': ɵɵsyntheticHostProperty,
  'ɵɵsyntheticHostListener': ɵɵsyntheticHostListener,
  'ɵɵpipeBind1': ɵɵpipeBind1,
  'ɵɵpipeBind2': ɵɵpipeBind2,
  'ɵɵpipeBind3': ɵɵpipeBind3,
  'ɵɵpipeBind4': ɵɵpipeBind4,
  'ɵɵpipeBindV': ɵɵpipeBindV,
  'ɵɵprojectionDef': ɵɵprojectionDef,
  'ɵɵdomProperty': ɵɵdomProperty,
  'ɵɵariaProperty': ɵɵariaProperty,
  'ɵɵproperty': ɵɵproperty,
  'ɵɵcontrol': ɵɵcontrol,
  'ɵɵcontrolCreate': ɵɵcontrolCreate,
  'ɵɵpipe': ɵɵpipe,
  'ɵɵqueryRefresh': ɵɵqueryRefresh,
  'ɵɵqueryAdvance': ɵɵqueryAdvance,
  'ɵɵviewQuery': ɵɵviewQuery,
  'ɵɵviewQuerySignal': ɵɵviewQuerySignal,
  'ɵɵloadQuery': ɵɵloadQuery,
  'ɵɵcontentQuery': ɵɵcontentQuery,
  'ɵɵcontentQuerySignal': ɵɵcontentQuerySignal,
  'ɵɵreference': ɵɵreference,
  'ɵɵclassMap': ɵɵclassMap,
  'ɵɵstyleMap': ɵɵstyleMap,
  'ɵɵstyleProp': ɵɵstyleProp,
  'ɵɵclassProp': ɵɵclassProp,
  'ɵɵadvance': ɵɵadvance,
  'ɵɵtemplate': ɵɵtemplate,
  'ɵɵconditional': ɵɵconditional,
  'ɵɵconditionalCreate': ɵɵconditionalCreate,
  'ɵɵconditionalBranchCreate': ɵɵconditionalBranchCreate,
  'ɵɵboundaryCreate': ɵɵboundaryCreate,
  'ɵɵboundaryUpdate': ɵɵboundaryUpdate,
  'ɵɵgetBoundary': ɵɵgetBoundary,
  'ɵɵdefer': ɵɵdefer,
  'ɵɵdeferWhen': ɵɵdeferWhen,
  'ɵɵdeferOnIdle': ɵɵdeferOnIdle,
  'ɵɵdeferOnImmediate': ɵɵdeferOnImmediate,
  'ɵɵdeferOnTimer': ɵɵdeferOnTimer,
  'ɵɵdeferOnHover': ɵɵdeferOnHover,
  'ɵɵdeferOnInteraction': ɵɵdeferOnInteraction,
  'ɵɵdeferOnViewport': ɵɵdeferOnViewport,
  'ɵɵdeferPrefetchWhen': ɵɵdeferPrefetchWhen,
  'ɵɵdeferPrefetchOnIdle': ɵɵdeferPrefetchOnIdle,
  'ɵɵdeferPrefetchOnImmediate': ɵɵdeferPrefetchOnImmediate,
  'ɵɵdeferPrefetchOnTimer': ɵɵdeferPrefetchOnTimer,
  'ɵɵdeferPrefetchOnHover': ɵɵdeferPrefetchOnHover,
  'ɵɵdeferPrefetchOnInteraction': ɵɵdeferPrefetchOnInteraction,
  'ɵɵdeferPrefetchOnViewport': ɵɵdeferPrefetchOnViewport,
  'ɵɵdeferHydrateWhen': ɵɵdeferHydrateWhen,
  'ɵɵdeferHydrateNever': ɵɵdeferHydrateNever,
  'ɵɵdeferHydrateOnIdle': ɵɵdeferHydrateOnIdle,
  'ɵɵdeferHydrateOnImmediate': ɵɵdeferHydrateOnImmediate,
  'ɵɵdeferHydrateOnTimer': ɵɵdeferHydrateOnTimer,
  'ɵɵdeferHydrateOnHover': ɵɵdeferHydrateOnHover,
  'ɵɵdeferHydrateOnInteraction': ɵɵdeferHydrateOnInteraction,
  'ɵɵdeferHydrateOnViewport': ɵɵdeferHydrateOnViewport,
  'ɵɵdeferEnableTimerScheduling': ɵɵdeferEnableTimerScheduling,
  'ɵɵenableIncrementalHydrationRuntime': ɵɵenableIncrementalHydrationRuntime,
  'ɵɵrepeater': ɵɵrepeater,
  'ɵɵrepeaterCreate': ɵɵrepeaterCreate,
  'ɵɵrepeaterTrackByIndex': ɵɵrepeaterTrackByIndex,
  'ɵɵrepeaterTrackByIdentity': ɵɵrepeaterTrackByIdentity,
  'ɵɵcomponentInstance': ɵɵcomponentInstance,
  'ɵɵtext': ɵɵtext,
  'ɵɵtextInterpolate': ɵɵtextInterpolate,
  'ɵɵtextInterpolate1': ɵɵtextInterpolate1,
  'ɵɵtextInterpolate2': ɵɵtextInterpolate2,
  'ɵɵtextInterpolate3': ɵɵtextInterpolate3,
  'ɵɵtextInterpolate4': ɵɵtextInterpolate4,
  'ɵɵtextInterpolate5': ɵɵtextInterpolate5,
  'ɵɵtextInterpolate6': ɵɵtextInterpolate6,
  'ɵɵtextInterpolate7': ɵɵtextInterpolate7,
  'ɵɵtextInterpolate8': ɵɵtextInterpolate8,
  'ɵɵtextInterpolateV': ɵɵtextInterpolateV,
  'ɵɵi18n': ɵɵi18n,
  'ɵɵi18nAttributes': ɵɵi18nAttributes,
  'ɵɵi18nExp': ɵɵi18nExp,
  'ɵɵi18nStart': ɵɵi18nStart,
  'ɵɵi18nEnd': ɵɵi18nEnd,
  'ɵɵi18nApply': ɵɵi18nApply,
  'ɵɵi18nPostprocess': ɵɵi18nPostprocess,
  'ɵɵresolveWindow': ɵɵresolveWindow,
  'ɵɵresolveDocument': ɵɵresolveDocument,
  'ɵɵresolveBody': ɵɵresolveBody,
  'ɵɵsetComponentScope': ɵɵsetComponentScope,
  'ɵɵsetNgModuleScope': ɵɵsetNgModuleScope,
  'ɵɵregisterNgModuleType': registerNgModuleType,
  'ɵɵgetComponentDepsFactory': ɵɵgetComponentDepsFactory,
  'ɵsetClassDebugInfo': ɵsetClassDebugInfo,
  'ɵɵdeclareLet': ɵɵdeclareLet,
  'ɵɵstoreLet': ɵɵstoreLet,
  'ɵɵarrowFunction': ɵɵarrowFunction,
  'ɵɵreadContextLet': ɵɵreadContextLet,
  'ɵɵattachSourceLocations': ɵɵattachSourceLocations,
  'ɵɵinterpolate': ɵɵinterpolate,
  'ɵɵinterpolate1': ɵɵinterpolate1,
  'ɵɵinterpolate2': ɵɵinterpolate2,
  'ɵɵinterpolate3': ɵɵinterpolate3,
  'ɵɵinterpolate4': ɵɵinterpolate4,
  'ɵɵinterpolate5': ɵɵinterpolate5,
  'ɵɵinterpolate6': ɵɵinterpolate6,
  'ɵɵinterpolate7': ɵɵinterpolate7,
  'ɵɵinterpolate8': ɵɵinterpolate8,
  'ɵɵinterpolateV': ɵɵinterpolateV,
  'ɵɵsanitizeHtml': ɵɵsanitizeHtml,
  'ɵɵsanitizeStyle': ɵɵsanitizeStyle,
  'ɵɵsanitizeResourceUrl': ɵɵsanitizeResourceUrl,
  'ɵɵsanitizeScript': ɵɵsanitizeScript,
  'ɵɵvalidateAttribute': ɵɵvalidateAttribute,
  'ɵɵsanitizeUrl': ɵɵsanitizeUrl,
  'ɵɵsanitizeUrlOrResourceUrl': ɵɵsanitizeUrlOrResourceUrl,
  'ɵɵtrustConstantHtml': ɵɵtrustConstantHtml,
  'ɵɵtrustConstantResourceUrl': ɵɵtrustConstantResourceUrl,
  'forwardRef': forwardRef,
  'resolveForwardRef': resolveForwardRef,
  'ɵɵtwoWayProperty': ɵɵtwoWayProperty,
  'ɵɵtwoWayBindingSet': ɵɵtwoWayBindingSet,
  'ɵɵtwoWayListener': ɵɵtwoWayListener,
  'ɵɵreplaceMetadata': ɵɵreplaceMetadata,
  'ɵɵgetReplaceMetadataURL': ɵɵgetReplaceMetadataURL
}))();

let jitOptions = null;
function setJitOptions(options) {
  if (jitOptions !== null) {
    if (options.defaultEncapsulation !== jitOptions.defaultEncapsulation) {
      ngDevMode && console.error('Provided value for `defaultEncapsulation` can not be changed once it has been set.');
      return;
    }
    if (options.preserveWhitespaces !== jitOptions.preserveWhitespaces) {
      ngDevMode && console.error('Provided value for `preserveWhitespaces` can not be changed once it has been set.');
      return;
    }
  }
  jitOptions = options;
}
function getJitOptions() {
  return jitOptions;
}
function resetJitOptions() {
  jitOptions = null;
}

const moduleQueue = [];
function enqueueModuleForDelayedScoping(moduleType, ngModule) {
  moduleQueue.push({
    moduleType,
    ngModule
  });
}
let flushingModuleQueue = false;
function flushModuleScopingQueueAsMuchAsPossible() {
  if (!flushingModuleQueue) {
    flushingModuleQueue = true;
    try {
      for (let i = moduleQueue.length - 1; i >= 0; i--) {
        const {
          moduleType,
          ngModule
        } = moduleQueue[i];
        if (ngModule.declarations && ngModule.declarations.every(isResolvedDeclaration)) {
          moduleQueue.splice(i, 1);
          setScopeOnDeclaredComponents(moduleType, ngModule);
        }
      }
    } finally {
      flushingModuleQueue = false;
    }
  }
}
function isResolvedDeclaration(declaration) {
  if (Array.isArray(declaration)) {
    return declaration.every(isResolvedDeclaration);
  }
  return !!resolveForwardRef(declaration);
}
function compileNgModule(moduleType, ngModule = {}) {
  compileNgModuleDefs(moduleType, ngModule);
  if (ngModule.id !== undefined) {
    registerNgModuleType(moduleType, ngModule.id);
  }
  enqueueModuleForDelayedScoping(moduleType, ngModule);
}
function compileNgModuleDefs(moduleType, ngModule, allowDuplicateDeclarationsInRoot = false) {
  ngDevMode && assertDefined(moduleType, 'Required value moduleType');
  ngDevMode && assertDefined(ngModule, 'Required value ngModule');
  const declarations = flatten(ngModule.declarations || EMPTY_ARRAY);
  let ngModuleDef = null;
  Object.defineProperty(moduleType, NG_MOD_DEF, {
    configurable: true,
    get: () => {
      if (ngModuleDef === null) {
        if (ngDevMode && ngModule.imports && ngModule.imports.indexOf(moduleType) > -1) {
          throw new Error(`'${stringifyForError(moduleType)}' module can't import itself`);
        }
        const compiler = getCompilerFacade({
          usage: 0,
          kind: 'NgModule',
          type: moduleType
        });
        ngModuleDef = compiler.compileNgModule(angularCoreEnv, `ng:///${moduleType.name}/ɵmod.js`, {
          type: moduleType,
          bootstrap: flatten(ngModule.bootstrap || EMPTY_ARRAY).map(resolveForwardRef),
          declarations: declarations.map(resolveForwardRef),
          imports: flatten(ngModule.imports || EMPTY_ARRAY).map(resolveForwardRef).map(expandModuleWithProviders),
          exports: flatten(ngModule.exports || EMPTY_ARRAY).map(resolveForwardRef).map(expandModuleWithProviders),
          schemas: ngModule.schemas ? flatten(ngModule.schemas) : null,
          id: ngModule.id || null
        });
        if (!ngModuleDef.schemas) {
          ngModuleDef.schemas = [];
        }
      }
      return ngModuleDef;
    }
  });
  let ngFactoryDef = null;
  Object.defineProperty(moduleType, NG_FACTORY_DEF, {
    get: () => {
      if (ngFactoryDef === null) {
        const compiler = getCompilerFacade({
          usage: 0,
          kind: 'NgModule',
          type: moduleType
        });
        ngFactoryDef = compiler.compileFactory(angularCoreEnv, `ng:///${moduleType.name}/ɵfac.js`, {
          name: moduleType.name,
          type: moduleType,
          deps: reflectDependencies(moduleType),
          target: compiler.FactoryTarget.NgModule,
          typeArgumentCount: 0
        });
      }
      return ngFactoryDef;
    },
    configurable: !!ngDevMode
  });
  let ngInjectorDef = null;
  Object.defineProperty(moduleType, NG_INJ_DEF, {
    get: () => {
      if (ngInjectorDef === null) {
        ngDevMode && verifySemanticsOfNgModuleDef(moduleType, allowDuplicateDeclarationsInRoot);
        const meta = {
          name: moduleType.name,
          type: moduleType,
          providers: ngModule.providers || EMPTY_ARRAY,
          imports: [(ngModule.imports || EMPTY_ARRAY).map(resolveForwardRef), (ngModule.exports || EMPTY_ARRAY).map(resolveForwardRef)]
        };
        const compiler = getCompilerFacade({
          usage: 0,
          kind: 'NgModule',
          type: moduleType
        });
        ngInjectorDef = compiler.compileInjector(angularCoreEnv, `ng:///${moduleType.name}/ɵinj.js`, meta);
      }
      return ngInjectorDef;
    },
    configurable: !!ngDevMode
  });
}
function generateStandaloneInDeclarationsError(type, location) {
  const prefix = `Unexpected "${stringifyForError(type)}" found in the "declarations" array of the`;
  const suffix = `"${stringifyForError(type)}" is marked as standalone and can't be declared ` + 'in any NgModule - did you intend to import it instead (by adding it to the "imports" array)?';
  return `${prefix} ${location}, ${suffix}`;
}
function verifySemanticsOfNgModuleDef(moduleType, allowDuplicateDeclarationsInRoot, importingModule) {
  if (verifiedNgModule.get(moduleType)) return;
  if (isStandalone(moduleType)) return;
  verifiedNgModule.set(moduleType, true);
  moduleType = resolveForwardRef(moduleType);
  let ngModuleDef;
  if (importingModule) {
    ngModuleDef = getNgModuleDef(moduleType);
    if (!ngModuleDef) {
      throw new Error(`Unexpected value '${moduleType.name}' imported by the module '${importingModule.name}'. Please add an @NgModule annotation.`);
    }
  } else {
    ngModuleDef = getNgModuleDefOrThrow(moduleType);
  }
  const errors = [];
  const declarations = maybeUnwrapFn(ngModuleDef.declarations);
  const imports = maybeUnwrapFn(ngModuleDef.imports);
  flatten(imports).map(unwrapModuleWithProvidersImports).forEach(modOrStandaloneCmpt => {
    verifySemanticsOfNgModuleImport(modOrStandaloneCmpt, moduleType);
    verifySemanticsOfNgModuleDef(modOrStandaloneCmpt, false, moduleType);
  });
  const exports = maybeUnwrapFn(ngModuleDef.exports);
  declarations.forEach(verifyDeclarationsHaveDefinitions);
  declarations.forEach(verifyDirectivesHaveSelector);
  declarations.forEach(declarationType => verifyNotStandalone(declarationType, moduleType));
  const combinedDeclarations = [...declarations.map(resolveForwardRef), ...flatten(imports.map(computeCombinedExports)).map(resolveForwardRef)];
  exports.forEach(verifyExportsAreDeclaredOrReExported);
  declarations.forEach(decl => verifyDeclarationIsUnique(decl, allowDuplicateDeclarationsInRoot));
  const ngModule = getAnnotation(moduleType, 'NgModule');
  if (ngModule) {
    ngModule.imports && flatten(ngModule.imports).map(unwrapModuleWithProvidersImports).forEach(mod => {
      verifySemanticsOfNgModuleImport(mod, moduleType);
      verifySemanticsOfNgModuleDef(mod, false, moduleType);
    });
    ngModule.bootstrap && deepForEach(ngModule.bootstrap, verifyCorrectBootstrapType);
    ngModule.bootstrap && deepForEach(ngModule.bootstrap, verifyComponentIsPartOfNgModule);
  }
  if (errors.length) {
    throw new Error(errors.join('\n'));
  }
  function verifyDeclarationsHaveDefinitions(type) {
    type = resolveForwardRef(type);
    const def = getComponentDef(type) || getDirectiveDef(type) || getPipeDef$1(type);
    if (!def) {
      errors.push(`Unexpected value '${stringifyForError(type)}' declared by the module '${stringifyForError(moduleType)}'. Please add a @Pipe/@Directive/@Component annotation.`);
    }
  }
  function verifyDirectivesHaveSelector(type) {
    type = resolveForwardRef(type);
    const def = getDirectiveDef(type);
    if (!getComponentDef(type) && !getPipeDef$1(type) && def && def.selectors.length == 0) {
      errors.push(`Directive ${stringifyForError(type)} has no selector, please add it!`);
    }
  }
  function verifyNotStandalone(type, moduleType) {
    type = resolveForwardRef(type);
    const def = getPipeDef$1(type) || getComponentDef(type) || getDirectiveDef(type);
    if (def?.standalone) {
      const location = `"${stringifyForError(moduleType)}" NgModule`;
      errors.push(generateStandaloneInDeclarationsError(type, location));
    }
  }
  function verifyExportsAreDeclaredOrReExported(type) {
    type = resolveForwardRef(type);
    const kind = getComponentDef(type) && 'component' || getDirectiveDef(type) && 'directive' || getPipeDef$1(type) && 'pipe';
    if (kind) {
      if (combinedDeclarations.lastIndexOf(type) === -1) {
        errors.push(`Can't export ${kind} ${stringifyForError(type)} from ${stringifyForError(moduleType)} as it was neither declared nor imported!`);
      }
    }
  }
  function verifyDeclarationIsUnique(type, suppressErrors) {
    type = resolveForwardRef(type);
    const existingModule = ownerNgModule.get(type);
    if (existingModule && existingModule !== moduleType) {
      if (!suppressErrors) {
        const modules = [existingModule, moduleType].map(stringifyForError).sort();
        errors.push(`Type ${stringifyForError(type)} is part of the declarations of 2 modules: ${modules[0]} and ${modules[1]}! ` + `Please consider moving ${stringifyForError(type)} to a higher module that imports ${modules[0]} and ${modules[1]}. ` + `You can also create a new NgModule that exports and includes ${stringifyForError(type)} then import that NgModule in ${modules[0]} and ${modules[1]}.`);
      }
    } else {
      ownerNgModule.set(type, moduleType);
    }
  }
  function verifyComponentIsPartOfNgModule(type) {
    type = resolveForwardRef(type);
    const existingModule = ownerNgModule.get(type);
    if (!existingModule && !isStandalone(type)) {
      errors.push(`Component ${stringifyForError(type)} is not part of any NgModule or the module has not been imported into your module.`);
    }
  }
  function verifyCorrectBootstrapType(type) {
    type = resolveForwardRef(type);
    if (!getComponentDef(type)) {
      errors.push(`${stringifyForError(type)} cannot be used as an entry component.`);
    }
    if (isStandalone(type)) {
      errors.push(`The \`${stringifyForError(type)}\` class is a standalone component, which can ` + `not be used in the \`@NgModule.bootstrap\` array. Use the \`bootstrapApplication\` ` + `function for bootstrap instead.`);
    }
  }
  function verifySemanticsOfNgModuleImport(type, importingModule) {
    type = resolveForwardRef(type);
    const directiveDef = getComponentDef(type) || getDirectiveDef(type);
    if (directiveDef !== null && !directiveDef.standalone) {
      throw new Error(`Unexpected directive '${type.name}' imported by the module '${importingModule.name}'. Please add an @NgModule annotation.`);
    }
    const pipeDef = getPipeDef$1(type);
    if (pipeDef !== null && !pipeDef.standalone) {
      throw new Error(`Unexpected pipe '${type.name}' imported by the module '${importingModule.name}'. Please add an @NgModule annotation.`);
    }
  }
}
function unwrapModuleWithProvidersImports(typeOrWithProviders) {
  typeOrWithProviders = resolveForwardRef(typeOrWithProviders);
  return typeOrWithProviders.ngModule || typeOrWithProviders;
}
function getAnnotation(type, name) {
  let annotation = null;
  collect(type.__annotations__);
  collect(type.decorators);
  return annotation;
  function collect(annotations) {
    if (annotations) {
      annotations.forEach(readAnnotation);
    }
  }
  function readAnnotation(decorator) {
    if (!annotation) {
      const proto = Object.getPrototypeOf(decorator);
      if (proto.ngMetadataName == name) {
        annotation = decorator;
      } else if (decorator.type) {
        const proto = Object.getPrototypeOf(decorator.type);
        if (proto.ngMetadataName == name) {
          annotation = decorator.args[0];
        }
      }
    }
  }
}
let ownerNgModule = new WeakMap();
let verifiedNgModule = new WeakMap();
function resetCompiledComponents() {
  ownerNgModule = new WeakMap();
  verifiedNgModule = new WeakMap();
  moduleQueue.length = 0;
  GENERATED_COMP_IDS.clear();
}
function computeCombinedExports(type) {
  type = resolveForwardRef(type);
  const ngModuleDef = getNgModuleDef(type);
  if (ngModuleDef === null) {
    return [type];
  }
  return flatten(maybeUnwrapFn(ngModuleDef.exports).map(type => {
    const ngModuleDef = getNgModuleDef(type);
    if (ngModuleDef) {
      verifySemanticsOfNgModuleDef(type, false);
      return computeCombinedExports(type);
    } else {
      return type;
    }
  }));
}
function setScopeOnDeclaredComponents(moduleType, ngModule) {
  const declarations = flatten(ngModule.declarations || EMPTY_ARRAY);
  const transitiveScopes = transitiveScopesFor(moduleType);
  declarations.forEach(declaration => {
    declaration = resolveForwardRef(declaration);
    if (Object.hasOwn(declaration, NG_COMP_DEF)) {
      const component = declaration;
      const componentDef = getComponentDef(component);
      patchComponentDefWithScope(componentDef, transitiveScopes);
    } else if (!Object.hasOwn(declaration, NG_DIR_DEF) && !Object.hasOwn(declaration, NG_PIPE_DEF)) {
      declaration.ngSelectorScope = moduleType;
    }
  });
}
function patchComponentDefWithScope(componentDef, transitiveScopes) {
  componentDef.directiveDefs = () => Array.from(transitiveScopes.compilation.directives).map(dir => Object.hasOwn(dir, NG_COMP_DEF) ? getComponentDef(dir) : getDirectiveDef(dir)).filter(def => !!def);
  componentDef.pipeDefs = () => Array.from(transitiveScopes.compilation.pipes).map(pipe => getPipeDef$1(pipe));
  componentDef.schemas = transitiveScopes.schemas;
  componentDef.tView = null;
}
function transitiveScopesFor(type) {
  if (isNgModule(type)) {
    const scope = depsTracker.getNgModuleScope(type);
    const def = getNgModuleDefOrThrow(type);
    return {
      schemas: def.schemas || null,
      ...scope
    };
  } else if (isStandalone(type)) {
    const directiveDef = getComponentDef(type) || getDirectiveDef(type);
    if (directiveDef !== null) {
      return {
        schemas: null,
        compilation: {
          directives: new Set(),
          pipes: new Set()
        },
        exported: {
          directives: new Set([type]),
          pipes: new Set()
        }
      };
    }
    const pipeDef = getPipeDef$1(type);
    if (pipeDef !== null) {
      return {
        schemas: null,
        compilation: {
          directives: new Set(),
          pipes: new Set()
        },
        exported: {
          directives: new Set(),
          pipes: new Set([type])
        }
      };
    }
  }
  throw new Error(`${type.name} does not have a module def (ɵmod property)`);
}
function expandModuleWithProviders(value) {
  if (isModuleWithProviders(value)) {
    return value.ngModule;
  }
  return value;
}

let compilationDepth = 0;
function compileComponent(type, metadata) {
  (typeof ngDevMode === 'undefined' || ngDevMode) && initNgDevMode();
  let ngComponentDef = null;
  maybeQueueResolutionOfComponentResources(type, metadata);
  addDirectiveFactoryDef(type, metadata);
  Object.defineProperty(type, NG_COMP_DEF, {
    get: () => {
      if (ngComponentDef === null) {
        const compiler = getCompilerFacade({
          usage: 0,
          kind: 'component',
          type: type
        });
        if (metadata.foreignImports !== undefined) {
          throw new Error(`Foreign components are not supported in JIT mode. ` + `Component '${type.name}' cannot specify 'foreignImports'.`);
        }
        if (componentNeedsResolution(metadata)) {
          const error = [`Component '${type.name}' is not resolved:`];
          if (metadata.templateUrl) {
            error.push(` - templateUrl: ${metadata.templateUrl}`);
          }
          if (metadata.styleUrls && metadata.styleUrls.length) {
            error.push(` - styleUrls: ${JSON.stringify(metadata.styleUrls)}`);
          }
          if (metadata.styleUrl) {
            error.push(` - styleUrl: ${metadata.styleUrl}`);
          }
          error.push(`Did you run and wait for 'resolveComponentResources()'?`);
          throw new Error(error.join('\n'));
        }
        const options = getJitOptions();
        let preserveWhitespaces = metadata.preserveWhitespaces;
        if (preserveWhitespaces === undefined) {
          if (options !== null && options.preserveWhitespaces !== undefined) {
            preserveWhitespaces = options.preserveWhitespaces;
          } else {
            preserveWhitespaces = false;
          }
        }
        let encapsulation = metadata.encapsulation;
        if (encapsulation === undefined) {
          if (options !== null && options.defaultEncapsulation !== undefined) {
            encapsulation = options.defaultEncapsulation;
          } else {
            encapsulation = ViewEncapsulation.Emulated;
          }
        }
        const templateUrl = metadata.templateUrl || `ng:///${type.name}/template.html`;
        const baseMeta = directiveMetadata(type, metadata);
        const meta = {
          ...baseMeta,
          typeSourceSpan: compiler.createParseSourceSpan('Component', type.name, templateUrl),
          template: metadata.template || '',
          preserveWhitespaces,
          styles: typeof metadata.styles === 'string' ? [metadata.styles] : metadata.styles || EMPTY_ARRAY,
          animations: metadata.animations,
          declarations: [],
          changeDetection: metadata.changeDetection,
          encapsulation,
          viewProviders: metadata.viewProviders || null,
          hasDirectiveDependencies: !baseMeta.isStandalone || metadata.imports != null && metadata.imports.length > 0
        };
        compilationDepth++;
        try {
          if (meta.usesInheritance) {
            addDirectiveDefToUndecoratedParents(type);
          }
          ngComponentDef = compiler.compileComponent(angularCoreEnv, templateUrl, meta);
          if (meta.isStandalone) {
            const imports = flatten(metadata.imports || EMPTY_ARRAY);
            const {
              directiveDefs,
              pipeDefs
            } = getStandaloneDefFunctions(type, imports);
            ngComponentDef.directiveDefs = directiveDefs;
            ngComponentDef.pipeDefs = pipeDefs;
            ngComponentDef.dependencies = () => imports.map(resolveForwardRef);
          }
        } finally {
          compilationDepth--;
        }
        if (compilationDepth === 0) {
          flushModuleScopingQueueAsMuchAsPossible();
        }
        if (hasSelectorScope(type)) {
          const scopes = transitiveScopesFor(type.ngSelectorScope);
          patchComponentDefWithScope(ngComponentDef, scopes);
        }
        if (metadata.schemas) {
          if (meta.isStandalone) {
            ngComponentDef.schemas = metadata.schemas;
          } else {
            throw new Error(`The 'schemas' was specified for the ${stringifyForError(type)} but is only valid on a component that is standalone.`);
          }
        } else if (meta.isStandalone) {
          ngComponentDef.schemas = [];
        }
      }
      return ngComponentDef;
    },
    set: def => {
      ngComponentDef = def;
    },
    configurable: !!ngDevMode
  });
}
function getStandaloneDefFunctions(type, imports) {
  const directiveDefs = () => {
    if (ngDevMode) {
      for (const rawDep of imports) {
        verifyStandaloneImport(rawDep, type);
      }
    }
    if (!isComponent(type)) {
      return [];
    }
    const scope = depsTracker.getStandaloneComponentScope(type, imports);
    return [...scope.compilation.directives].map(p => getComponentDef(p) || getDirectiveDef(p)).filter(d => d !== null);
  };
  const pipeDefs = () => {
    if (ngDevMode) {
      for (const rawDep of imports) {
        verifyStandaloneImport(rawDep, type);
      }
    }
    if (!isComponent(type)) {
      return [];
    }
    const scope = depsTracker.getStandaloneComponentScope(type, imports);
    return [...scope.compilation.pipes].map(p => getPipeDef$1(p)).filter(d => d !== null);
  };
  return {
    directiveDefs,
    pipeDefs
  };
}
function hasSelectorScope(component) {
  return component.ngSelectorScope !== undefined;
}
function compileDirective(type, directive) {
  let ngDirectiveDef = null;
  addDirectiveFactoryDef(type, directive || {});
  Object.defineProperty(type, NG_DIR_DEF, {
    get: () => {
      if (ngDirectiveDef === null) {
        const meta = getDirectiveMetadata(type, directive || {});
        const compiler = getCompilerFacade({
          usage: 0,
          kind: 'directive',
          type
        });
        ngDirectiveDef = compiler.compileDirective(angularCoreEnv, meta.sourceMapUrl, meta.metadata);
      }
      return ngDirectiveDef;
    },
    configurable: !!ngDevMode
  });
}
function getDirectiveMetadata(type, metadata) {
  const name = type && type.name;
  const sourceMapUrl = `ng:///${name}/ɵdir.js`;
  const compiler = getCompilerFacade({
    usage: 0,
    kind: 'directive',
    type
  });
  const facade = directiveMetadata(type, metadata);
  facade.typeSourceSpan = compiler.createParseSourceSpan('Directive', name, sourceMapUrl);
  if (facade.usesInheritance) {
    addDirectiveDefToUndecoratedParents(type);
  }
  return {
    metadata: facade,
    sourceMapUrl
  };
}
function addDirectiveFactoryDef(type, metadata) {
  let ngFactoryDef = null;
  Object.defineProperty(type, NG_FACTORY_DEF, {
    get: () => {
      if (ngFactoryDef === null) {
        const meta = getDirectiveMetadata(type, metadata);
        const compiler = getCompilerFacade({
          usage: 0,
          kind: 'directive',
          type
        });
        ngFactoryDef = compiler.compileFactory(angularCoreEnv, `ng:///${type.name}/ɵfac.js`, {
          name: meta.metadata.name,
          type: meta.metadata.type,
          typeArgumentCount: 0,
          deps: reflectDependencies(type),
          target: compiler.FactoryTarget.Directive
        });
      }
      return ngFactoryDef;
    },
    configurable: !!ngDevMode
  });
}
function extendsDirectlyFromObject(type) {
  return Object.getPrototypeOf(type.prototype) === Object.prototype;
}
function directiveMetadata(type, metadata) {
  const reflect = getReflect();
  const propMetadata = reflect.ownPropMetadata(type);
  return {
    name: type.name,
    legacyOptionalChaining: false,
    type: type,
    selector: metadata.selector !== undefined ? metadata.selector : null,
    host: metadata.host || EMPTY_OBJ,
    propMetadata: propMetadata,
    inputs: metadata.inputs || EMPTY_ARRAY,
    outputs: metadata.outputs || EMPTY_ARRAY,
    queries: extractQueriesMetadata(type, propMetadata, isContentQuery),
    lifecycle: {
      usesOnChanges: reflect.hasLifecycleHook(type, 'ngOnChanges')
    },
    controlCreate: reflect.hasLifecycleHook(type, 'ɵngControlCreate') ? {
      passThroughInput: null
    } : null,
    typeSourceSpan: null,
    usesInheritance: !extendsDirectlyFromObject(type),
    exportAs: extractExportAs(metadata.exportAs),
    providers: metadata.providers || null,
    viewQueries: extractQueriesMetadata(type, propMetadata, isViewQuery),
    isStandalone: metadata.standalone === undefined ? true : !!metadata.standalone,
    isSignal: !!metadata.signals,
    hostDirectives: metadata.hostDirectives?.map(directive => typeof directive === 'function' ? {
      directive
    } : directive) || null
  };
}
function addDirectiveDefToUndecoratedParents(type) {
  const objPrototype = Object.prototype;
  let parent = Object.getPrototypeOf(type.prototype).constructor;
  while (parent && parent !== objPrototype) {
    if (!getDirectiveDef(parent) && !getComponentDef(parent) && shouldAddAbstractDirective(parent)) {
      compileDirective(parent, null);
    }
    parent = Object.getPrototypeOf(parent);
  }
}
function convertToR3QueryPredicate(selector) {
  return typeof selector === 'string' ? splitByComma(selector) : resolveForwardRef(selector);
}
function convertToR3QueryMetadata(propertyName, ann) {
  return {
    propertyName: propertyName,
    predicate: convertToR3QueryPredicate(ann.selector),
    descendants: ann.descendants,
    first: ann.first,
    read: ann.read ? ann.read : null,
    static: !!ann.static,
    emitDistinctChangesOnly: !!ann.emitDistinctChangesOnly,
    isSignal: !!ann.isSignal
  };
}
function extractQueriesMetadata(type, propMetadata, isQueryAnn) {
  const signalQueriesMeta = [];
  const decoratorQueriesMeta = [];
  for (const field in propMetadata) {
    if (Object.hasOwn(propMetadata, field)) {
      const annotations = propMetadata[field];
      annotations.forEach(ann => {
        if (isQueryAnn(ann)) {
          if (!ann.selector) {
            throw new Error(`Can't construct a query for the property "${field}" of ` + `"${stringifyForError(type)}" since the query selector wasn't defined.`);
          }
          if (annotations.some(isInputAnnotation)) {
            throw new Error(`Cannot combine @Input decorators with query decorators`);
          }
          const queryMeta = convertToR3QueryMetadata(field, ann);
          if (queryMeta.isSignal) {
            signalQueriesMeta.push(queryMeta);
          } else {
            decoratorQueriesMeta.push(queryMeta);
          }
        }
      });
    }
  }
  return [...signalQueriesMeta, ...decoratorQueriesMeta];
}
function extractExportAs(exportAs) {
  return exportAs === undefined ? null : splitByComma(exportAs);
}
function isContentQuery(value) {
  const name = value.ngMetadataName;
  return name === 'ContentChild' || name === 'ContentChildren';
}
function isViewQuery(value) {
  const name = value.ngMetadataName;
  return name === 'ViewChild' || name === 'ViewChildren';
}
function isInputAnnotation(value) {
  return value.ngMetadataName === 'Input';
}
function splitByComma(value) {
  return value.split(',').map(piece => piece.trim());
}
const LIFECYCLE_HOOKS = ['ngOnChanges', 'ngOnInit', 'ngOnDestroy', 'ngDoCheck', 'ngAfterViewInit', 'ngAfterViewChecked', 'ngAfterContentInit', 'ngAfterContentChecked'];
function shouldAddAbstractDirective(type) {
  const reflect = getReflect();
  if (LIFECYCLE_HOOKS.some(hookName => reflect.hasLifecycleHook(type, hookName))) {
    return true;
  }
  const propMetadata = reflect.propMetadata(type);
  for (const field in propMetadata) {
    const annotations = propMetadata[field];
    for (let i = 0; i < annotations.length; i++) {
      const current = annotations[i];
      const metadataName = current.ngMetadataName;
      if (isInputAnnotation(current) || isContentQuery(current) || isViewQuery(current) || metadataName === 'Output' || metadataName === 'HostBinding' || metadataName === 'HostListener') {
        return true;
      }
    }
  }
  return false;
}

function compilePipe(type, meta) {
  let ngPipeDef = null;
  let ngFactoryDef = null;
  Object.defineProperty(type, NG_FACTORY_DEF, {
    get: () => {
      if (ngFactoryDef === null) {
        const metadata = getPipeMetadata(type, meta);
        const compiler = getCompilerFacade({
          usage: 0,
          kind: 'pipe',
          type: metadata.type
        });
        ngFactoryDef = compiler.compileFactory(angularCoreEnv, `ng:///${metadata.name}/ɵfac.js`, {
          name: metadata.name,
          type: metadata.type,
          typeArgumentCount: 0,
          deps: reflectDependencies(type),
          target: compiler.FactoryTarget.Pipe
        });
      }
      return ngFactoryDef;
    },
    configurable: !!ngDevMode
  });
  Object.defineProperty(type, NG_PIPE_DEF, {
    get: () => {
      if (ngPipeDef === null) {
        const metadata = getPipeMetadata(type, meta);
        const compiler = getCompilerFacade({
          usage: 0,
          kind: 'pipe',
          type: metadata.type
        });
        ngPipeDef = compiler.compilePipe(angularCoreEnv, `ng:///${metadata.name}/ɵpipe.js`, metadata);
      }
      return ngPipeDef;
    },
    configurable: !!ngDevMode
  });
}
function getPipeMetadata(type, meta) {
  return {
    type: type,
    name: type.name,
    pipeName: meta.name,
    pure: meta.pure !== undefined ? meta.pure : true,
    isStandalone: meta.standalone === undefined ? true : !!meta.standalone
  };
}

const Directive = makeDecorator('Directive', (dir = {}) => dir, undefined, undefined, (type, meta) => compileDirective(type, meta));
const Component = makeDecorator('Component', (c = {}) => ({
  changeDetection: ChangeDetectionStrategy.Eager,
  ...c
}), Directive, undefined, (type, meta) => compileComponent(type, meta));
const Pipe = makeDecorator('Pipe', p => ({
  pure: true,
  ...p
}), undefined, undefined, (type, meta) => compilePipe(type, meta));
const Input = makePropDecorator('Input', arg => {
  if (!arg) {
    return {};
  }
  return typeof arg === 'string' ? {
    alias: arg
  } : arg;
});
const Output = makePropDecorator('Output', alias => ({
  alias
}));
const HostBinding = makePropDecorator('HostBinding', hostPropertyName => ({
  hostPropertyName
}));
const HostListener = makePropDecorator('HostListener', (eventName, args) => ({
  eventName,
  args
}));

const NgModule = makeDecorator('NgModule', ngModule => ngModule, undefined, undefined, (type, meta) => compileNgModule(type, meta));

const CONSECUTIVE_MICROTASK_NOTIFICATION_LIMIT = 100;
let consecutiveMicrotaskNotifications = 0;
let stackFromLastFewNotifications = [];
function trackMicrotaskNotificationForDebugging() {
  consecutiveMicrotaskNotifications++;
  if (CONSECUTIVE_MICROTASK_NOTIFICATION_LIMIT - consecutiveMicrotaskNotifications < 5) {
    const stack = new Error().stack;
    if (stack) {
      stackFromLastFewNotifications.push(stack);
    }
  }
  if (consecutiveMicrotaskNotifications === CONSECUTIVE_MICROTASK_NOTIFICATION_LIMIT) {
    throw new RuntimeError(103, 'Angular could not stabilize because there were endless change notifications within the browser event loop. ' + 'The stack from the last several notifications: \n' + stackFromLastFewNotifications.join('\n'));
  }
}
class ChangeDetectionSchedulerImpl {
  applicationErrorHandler = inject(INTERNAL_APPLICATION_ERROR_HANDLER);
  appRef = inject(ApplicationRef);
  taskService = inject(PendingTasksInternal);
  ngZone = inject(NgZone);
  zonelessEnabled = inject(ZONELESS_ENABLED);
  tracing = inject(TracingService, {
    optional: true
  });
  zoneIsDefined = typeof Zone !== 'undefined' && !!Zone.root.run;
  schedulerTickApplyArgs = [{
    data: {
      '__scheduler_tick__': true
    }
  }];
  subscriptions = new Subscription();
  angularZoneId = this.zoneIsDefined ? this.ngZone._inner?.get(angularZoneInstanceIdProperty) : null;
  scheduleInRootZone = !this.zonelessEnabled && this.zoneIsDefined && (inject(SCHEDULE_IN_ROOT_ZONE, {
    optional: true
  }) ?? false);
  cancelScheduledCallback = null;
  useMicrotaskScheduler = false;
  runningTick = false;
  pendingRenderTaskId = null;
  constructor() {
    this.subscriptions.add(this.appRef.afterTick.subscribe(() => {
      const task = this.taskService.add();
      if (!this.runningTick) {
        this.cleanup();
        if (!this.zonelessEnabled || this.appRef.includeAllTestViews) {
          this.taskService.remove(task);
          return;
        }
      }
      this.switchToMicrotaskScheduler();
      this.taskService.remove(task);
    }));
    this.subscriptions.add(this.ngZone.onUnstable.subscribe(() => {
      if (!this.runningTick) {
        this.cleanup();
      }
    }));
  }
  switchToMicrotaskScheduler() {
    this.ngZone.runOutsideAngular(() => {
      const task = this.taskService.add();
      this.useMicrotaskScheduler = true;
      queueMicrotask(() => {
        this.useMicrotaskScheduler = false;
        this.taskService.remove(task);
      });
    });
  }
  notify(source) {
    if (!this.zonelessEnabled && source === 5) {
      return;
    }
    switch (source) {
      case 0:
      case 2:
        {
          this.appRef.dirtyFlags |= 2;
          break;
        }
      case 3:
      case 4:
      case 5:
      case 1:
        {
          this.appRef.dirtyFlags |= 4;
          break;
        }
      case 6:
        {
          this.appRef.dirtyFlags |= 2;
          break;
        }
      case 12:
        {
          this.appRef.dirtyFlags |= 16;
          break;
        }
      case 13:
        {
          this.appRef.dirtyFlags |= 2;
          break;
        }
      case 11:
        {
          break;
        }
      case 9:
      case 8:
      case 7:
      case 10:
      default:
        {
          this.appRef.dirtyFlags |= 8;
        }
    }
    this.appRef.tracingSnapshot = this.tracing?.snapshot(this.appRef.tracingSnapshot) ?? null;
    if (!this.shouldScheduleTick()) {
      return;
    }
    if (typeof ngDevMode === 'undefined' || ngDevMode) {
      if (this.useMicrotaskScheduler) {
        trackMicrotaskNotificationForDebugging();
      } else {
        consecutiveMicrotaskNotifications = 0;
        stackFromLastFewNotifications.length = 0;
      }
    }
    const scheduleCallback = this.useMicrotaskScheduler ? scheduleCallbackWithMicrotask : scheduleCallbackWithRafRace;
    this.pendingRenderTaskId = this.taskService.add();
    if (this.scheduleInRootZone) {
      this.cancelScheduledCallback = Zone.root.run(() => scheduleCallback(() => this.tick()));
    } else {
      this.cancelScheduledCallback = this.ngZone.runOutsideAngular(() => scheduleCallback(() => this.tick()));
    }
  }
  shouldScheduleTick() {
    if (this.appRef.destroyed) {
      return false;
    }
    if (this.pendingRenderTaskId !== null || this.runningTick || this.appRef._runningTick) {
      return false;
    }
    if (!this.zonelessEnabled && this.zoneIsDefined && Zone.current.get(angularZoneInstanceIdProperty + this.angularZoneId)) {
      return false;
    }
    return true;
  }
  tick() {
    if (this.runningTick || this.appRef.destroyed) {
      return;
    }
    if (this.appRef.dirtyFlags === 0) {
      this.cleanup();
      return;
    }
    if (!this.zonelessEnabled && this.appRef.dirtyFlags & 7) {
      this.appRef.dirtyFlags |= 1;
    }
    const task = this.taskService.add();
    try {
      this.ngZone.run(() => {
        this.runningTick = true;
        this.appRef._tick();
      }, undefined, this.schedulerTickApplyArgs);
    } catch (e) {
      this.applicationErrorHandler(e);
    } finally {
      this.taskService.remove(task);
      this.cleanup();
    }
  }
  ngOnDestroy() {
    this.subscriptions.unsubscribe();
    this.cleanup();
  }
  cleanup() {
    this.runningTick = false;
    this.cancelScheduledCallback?.();
    this.cancelScheduledCallback = null;
    if (this.pendingRenderTaskId !== null) {
      const taskId = this.pendingRenderTaskId;
      this.pendingRenderTaskId = null;
      this.taskService.remove(taskId);
    }
  }
  static ɵfac = function ChangeDetectionSchedulerImpl_Factory(__ngFactoryType__) {
    return new (__ngFactoryType__ || ChangeDetectionSchedulerImpl)();
  };
  static ɵprov = /*@__PURE__*/ɵɵdefineService({
    token: ChangeDetectionSchedulerImpl,
    factory: ChangeDetectionSchedulerImpl.ɵfac
  });
}
(() => {
  (typeof ngDevMode === "undefined" || ngDevMode) && setClassMetadata(ChangeDetectionSchedulerImpl, [{
    type: Service
  }], () => [], null);
})();
function provideZonelessChangeDetection() {
  performanceMarkFeature('NgZoneless');
  if ((typeof ngDevMode === 'undefined' || ngDevMode) && typeof Zone !== 'undefined' && Zone) {
    const message = formatRuntimeError(914, `The application is using zoneless change detection, but is still loading Zone.js. ` + `Consider removing Zone.js to get the full benefits of zoneless. ` + `In applications using the Angular CLI, Zone.js is typically included in the "polyfills" section of the angular.json file.`);
    console.warn(message);
  }
  return makeEnvironmentProviders([...provideZonelessChangeDetectionInternal(), typeof ngDevMode === 'undefined' || ngDevMode ? [{
    provide: PROVIDED_ZONELESS,
    useValue: true
  }] : []]);
}
function provideZonelessChangeDetectionInternal() {
  return [{
    provide: ChangeDetectionScheduler,
    useExisting: ChangeDetectionSchedulerImpl
  }, {
    provide: NgZone,
    useClass: NoopNgZone
  }, {
    provide: ZONELESS_ENABLED,
    useValue: true
  }];
}

class Compiler {
  compileModuleSync(moduleType) {
    return new NgModuleFactory(moduleType);
  }
  compileModuleAsync(moduleType) {
    return Promise.resolve(this.compileModuleSync(moduleType));
  }
  clearCache() {}
  clearCacheFor(type) {}
  getModuleId(moduleType) {
    return undefined;
  }
  static ɵfac = function Compiler_Factory(__ngFactoryType__) {
    return new (__ngFactoryType__ || Compiler)();
  };
  static ɵprov = /*@__PURE__*/ɵɵdefineService({
    token: Compiler,
    factory: Compiler.ɵfac
  });
}
(() => {
  (typeof ngDevMode === "undefined" || ngDevMode) && setClassMetadata(Compiler, [{
    type: Service
  }], null, null);
})();
const COMPILER_OPTIONS = new InjectionToken(typeof ngDevMode !== 'undefined' && ngDevMode ? 'compilerOptions' : '');
class CompilerFactory {}

function getGlobalLocale() {
  if (typeof ngI18nClosureMode !== 'undefined' && ngI18nClosureMode && typeof goog !== 'undefined' && goog.LOCALE !== 'en') {
    return goog.LOCALE;
  } else {
    return typeof $localize !== 'undefined' && $localize.locale || DEFAULT_LOCALE_ID;
  }
}
const LOCALE_ID = new InjectionToken(typeof ngDevMode !== 'undefined' && ngDevMode ? 'LocaleId' : '', {
  factory: () => inject(LOCALE_ID, {
    optional: true,
    skipSelf: true
  }) || getGlobalLocale()
});
const DEFAULT_CURRENCY_CODE = new InjectionToken(typeof ngDevMode !== 'undefined' && ngDevMode ? 'DefaultCurrencyCode' : '', {
  factory: () => USD_CURRENCY_CODE
});
const TRANSLATIONS = new InjectionToken(typeof ngDevMode !== 'undefined' && ngDevMode ? 'Translations' : '');
const TRANSLATIONS_FORMAT = new InjectionToken(typeof ngDevMode !== 'undefined' && ngDevMode ? 'TranslationsFormat' : '');
var MissingTranslationStrategy;
(function (MissingTranslationStrategy) {
  MissingTranslationStrategy[MissingTranslationStrategy["Error"] = 0] = "Error";
  MissingTranslationStrategy[MissingTranslationStrategy["Warning"] = 1] = "Warning";
  MissingTranslationStrategy[MissingTranslationStrategy["Ignore"] = 2] = "Ignore";
})(MissingTranslationStrategy || (MissingTranslationStrategy = {}));

function getDeferBlocks(lView, deferBlocks) {
  const tView = lView[TVIEW$1];
  for (let i = HEADER_OFFSET; i < tView.bindingStartIndex; i++) {
    if (isLContainer(lView[i])) {
      const lContainer = lView[i];
      const isLast = i === tView.bindingStartIndex - 1;
      if (!isLast) {
        const tNode = tView.data[i];
        const tDetails = getTDeferBlockDetails(tView, tNode);
        if (isTDeferBlockDetails(tDetails)) {
          deferBlocks.push({
            lContainer,
            lView,
            tNode,
            tDetails
          });
          continue;
        }
      }
      if (isLView(lContainer[HOST])) {
        getDeferBlocks(lContainer[HOST], deferBlocks);
      }
      for (let j = CONTAINER_HEADER_OFFSET; j < lContainer.length; j++) {
        getDeferBlocks(lContainer[j], deferBlocks);
      }
    } else if (isLView(lView[i])) {
      getDeferBlocks(lView[i], deferBlocks);
    }
  }
}

class DebugEventListener {
  name;
  callback;
  constructor(name, callback) {
    this.name = name;
    this.callback = callback;
  }
}
function asNativeElements(debugEls) {
  return debugEls.map(el => el.nativeElement);
}
class DebugNode {
  nativeNode;
  constructor(nativeNode) {
    this.nativeNode = nativeNode;
  }
  get parent() {
    const parent = this.nativeNode.parentNode;
    return parent ? new DebugElement(parent) : null;
  }
  get injector() {
    return getInjector(this.nativeNode);
  }
  get componentInstance() {
    const nativeElement = this.nativeNode;
    return nativeElement && (getComponent(nativeElement) || getOwningComponent(nativeElement));
  }
  get context() {
    return getComponent(this.nativeNode) || getContext(this.nativeNode);
  }
  get listeners() {
    return getListeners(this.nativeNode).filter(listener => listener.type === 'dom');
  }
  get references() {
    return getLocalRefs(this.nativeNode);
  }
  get providerTokens() {
    return getInjectionTokens(this.nativeNode);
  }
}
class DebugElement extends DebugNode {
  constructor(nativeNode) {
    ngDevMode && assertDomNode(nativeNode);
    super(nativeNode);
  }
  get nativeElement() {
    return this.nativeNode.nodeType == Node.ELEMENT_NODE ? this.nativeNode : null;
  }
  get name() {
    const context = getLContext(this.nativeNode);
    const lView = context ? context.lView : null;
    if (lView !== null) {
      const tData = lView[TVIEW$1].data;
      const tNode = tData[context.nodeIndex];
      return tNode.value;
    } else {
      return this.nativeNode.nodeName;
    }
  }
  get properties() {
    const context = getLContext(this.nativeNode);
    const lView = context ? context.lView : null;
    if (lView === null) {
      return {};
    }
    const tData = lView[TVIEW$1].data;
    const tNode = tData[context.nodeIndex];
    const properties = {};
    copyDomProperties(this.nativeElement, properties);
    collectPropertyBindings(properties, tNode, lView, tData);
    return properties;
  }
  get attributes() {
    const attributes = {};
    const element = this.nativeElement;
    if (!element) {
      return attributes;
    }
    const context = getLContext(element);
    const lView = context ? context.lView : null;
    if (lView === null) {
      return {};
    }
    const tNodeAttrs = lView[TVIEW$1].data[context.nodeIndex].attrs;
    const lowercaseTNodeAttrs = [];
    if (tNodeAttrs) {
      let i = 0;
      while (i < tNodeAttrs.length) {
        const attrName = tNodeAttrs[i];
        if (typeof attrName !== 'string') break;
        const attrValue = tNodeAttrs[i + 1];
        attributes[attrName] = attrValue;
        lowercaseTNodeAttrs.push(attrName.toLowerCase());
        i += 2;
      }
    }
    for (const attr of element.attributes) {
      if (!lowercaseTNodeAttrs.includes(attr.name)) {
        attributes[attr.name] = attr.value;
      }
    }
    return attributes;
  }
  get styles() {
    const element = this.nativeElement;
    return element?.style ?? {};
  }
  get classes() {
    const result = {};
    const element = this.nativeElement;
    const className = element.className;
    const classes = typeof className !== 'string' ? className.baseVal.split(' ') : className.split(' ');
    classes.forEach(value => result[value] = true);
    return result;
  }
  get childNodes() {
    const childNodes = this.nativeNode.childNodes;
    const children = [];
    for (let i = 0; i < childNodes.length; i++) {
      const element = childNodes[i];
      children.push(getDebugNode(element));
    }
    return children;
  }
  get children() {
    const nativeElement = this.nativeElement;
    if (!nativeElement) return [];
    const childNodes = nativeElement.children;
    const children = [];
    for (let i = 0; i < childNodes.length; i++) {
      const element = childNodes[i];
      children.push(getDebugNode(element));
    }
    return children;
  }
  query(predicate) {
    const results = this.queryAll(predicate);
    return results[0] || null;
  }
  queryAll(predicate) {
    const matches = [];
    _queryAll(this, predicate, matches, true);
    return matches;
  }
  queryAllNodes(predicate) {
    const matches = [];
    _queryAll(this, predicate, matches, false);
    return matches;
  }
  triggerEventHandler(eventName, eventObj) {
    const node = this.nativeNode;
    const invokedListeners = [];
    this.listeners.forEach(listener => {
      if (listener.name === eventName) {
        const callback = listener.callback;
        callback.call(node, eventObj);
        invokedListeners.push(callback);
      }
    });
    if (typeof node.eventListeners === 'function') {
      node.eventListeners(eventName).forEach(listener => {
        if (listener.toString().indexOf('__ngUnwrap__') !== -1) {
          const unwrappedListener = listener('__ngUnwrap__');
          return invokedListeners.indexOf(unwrappedListener) === -1 && unwrappedListener.call(node, eventObj);
        }
      });
    }
  }
}
function copyDomProperties(element, properties) {
  if (element) {
    let obj = Object.getPrototypeOf(element);
    const NodePrototype = Node.prototype;
    while (obj !== null && obj !== NodePrototype) {
      const descriptors = Object.getOwnPropertyDescriptors(obj);
      for (let key in descriptors) {
        if (!key.startsWith('__') && !key.startsWith('on')) {
          const value = element[key];
          if (isPrimitiveValue(value)) {
            properties[key] = value;
          }
        }
      }
      obj = Object.getPrototypeOf(obj);
    }
  }
}
function isPrimitiveValue(value) {
  return typeof value === 'string' || typeof value === 'boolean' || typeof value === 'number' || value === null;
}
function _queryAll(parentElement, predicate, matches, elementsOnly) {
  const context = getLContext(parentElement.nativeNode);
  const lView = context ? context.lView : null;
  if (lView !== null) {
    const parentTNode = lView[TVIEW$1].data[context.nodeIndex];
    _queryNodeChildren(parentTNode, lView, predicate, matches, elementsOnly, parentElement.nativeNode);
  } else {
    _queryNativeNodeDescendants(parentElement.nativeNode, predicate, matches, elementsOnly);
  }
}
function _queryNodeChildren(tNode, lView, predicate, matches, elementsOnly, rootNativeNode) {
  ngDevMode && assertTNodeForLView(tNode, lView);
  const nativeNode = getNativeByTNodeOrNull(tNode, lView);
  if (tNode.type & (3 | 8)) {
    _addQueryMatch(nativeNode, predicate, matches, elementsOnly, rootNativeNode);
    if (isComponentHost(tNode)) {
      const componentView = getComponentLViewByIndex(tNode.index, lView);
      if (componentView && componentView[TVIEW$1].firstChild) {
        _queryNodeChildren(componentView[TVIEW$1].firstChild, componentView, predicate, matches, elementsOnly, rootNativeNode);
      }
    } else {
      if (tNode.child) {
        _queryNodeChildren(tNode.child, lView, predicate, matches, elementsOnly, rootNativeNode);
      }
      nativeNode && _queryNativeNodeDescendants(nativeNode, predicate, matches, elementsOnly);
    }
    const nodeOrContainer = lView[tNode.index];
    if (isLContainer(nodeOrContainer)) {
      _queryNodeChildrenInContainer(nodeOrContainer, predicate, matches, elementsOnly, rootNativeNode);
    }
  } else if (tNode.type & 4) {
    const lContainer = lView[tNode.index];
    _addQueryMatch(lContainer[NATIVE], predicate, matches, elementsOnly, rootNativeNode);
    _queryNodeChildrenInContainer(lContainer, predicate, matches, elementsOnly, rootNativeNode);
  } else if (tNode.type & 16) {
    const componentView = lView[DECLARATION_COMPONENT_VIEW];
    const componentHost = componentView[T_HOST];
    const head = componentHost.projection[tNode.projection];
    if (Array.isArray(head)) {
      for (let nativeNode of head) {
        _addQueryMatch(nativeNode, predicate, matches, elementsOnly, rootNativeNode);
      }
    } else if (head) {
      const nextLView = componentView[PARENT];
      const nextTNode = nextLView[TVIEW$1].data[head.index];
      _queryNodeChildren(nextTNode, nextLView, predicate, matches, elementsOnly, rootNativeNode);
    }
  } else if (tNode.child) {
    _queryNodeChildren(tNode.child, lView, predicate, matches, elementsOnly, rootNativeNode);
  }
  if (rootNativeNode !== nativeNode) {
    const nextTNode = tNode.flags & 2 ? tNode.projectionNext : tNode.next;
    if (nextTNode) {
      _queryNodeChildren(nextTNode, lView, predicate, matches, elementsOnly, rootNativeNode);
    }
  }
}
function _queryNodeChildrenInContainer(lContainer, predicate, matches, elementsOnly, rootNativeNode) {
  for (let i = CONTAINER_HEADER_OFFSET; i < lContainer.length; i++) {
    const childView = lContainer[i];
    const firstChild = childView[TVIEW$1].firstChild;
    if (firstChild) {
      _queryNodeChildren(firstChild, childView, predicate, matches, elementsOnly, rootNativeNode);
    }
  }
}
function _addQueryMatch(nativeNode, predicate, matches, elementsOnly, rootNativeNode) {
  if (rootNativeNode !== nativeNode) {
    const debugNode = getDebugNode(nativeNode);
    if (!debugNode) {
      return;
    }
    if (elementsOnly && debugNode instanceof DebugElement && predicate(debugNode) && matches.indexOf(debugNode) === -1) {
      matches.push(debugNode);
    } else if (!elementsOnly && predicate(debugNode) && matches.indexOf(debugNode) === -1) {
      matches.push(debugNode);
    }
  }
}
function _queryNativeNodeDescendants(parentNode, predicate, matches, elementsOnly) {
  const nodes = parentNode.childNodes;
  const length = nodes.length;
  for (let i = 0; i < length; i++) {
    const node = nodes[i];
    const debugNode = getDebugNode(node);
    if (debugNode) {
      if (elementsOnly && debugNode instanceof DebugElement && predicate(debugNode) && matches.indexOf(debugNode) === -1) {
        matches.push(debugNode);
      } else if (!elementsOnly && predicate(debugNode) && matches.indexOf(debugNode) === -1) {
        matches.push(debugNode);
      }
      _queryNativeNodeDescendants(node, predicate, matches, elementsOnly);
    }
  }
}
function collectPropertyBindings(properties, tNode, lView, tData) {
  let bindingIndexes = tNode.propertyBindings;
  if (bindingIndexes !== null) {
    for (let i = 0; i < bindingIndexes.length; i++) {
      const bindingIndex = bindingIndexes[i];
      const propMetadata = tData[bindingIndex];
      const metadataParts = propMetadata.split(INTERPOLATION_DELIMITER);
      const propertyName = metadataParts[0];
      if (metadataParts.length > 1) {
        let value = metadataParts[1];
        for (let j = 1; j < metadataParts.length - 1; j++) {
          value += renderStringify(lView[bindingIndex + j - 1]) + metadataParts[j + 1];
        }
        properties[propertyName] = value;
      } else {
        properties[propertyName] = lView[bindingIndex];
      }
    }
  }
}
const NG_DEBUG_PROPERTY = '__ng_debug__';
function getDebugNode(nativeNode) {
  if (nativeNode instanceof Node) {
    if (!Object.hasOwn(nativeNode, NG_DEBUG_PROPERTY)) {
      nativeNode[NG_DEBUG_PROPERTY] = nativeNode.nodeType == Node.ELEMENT_NODE ? new DebugElement(nativeNode) : new DebugNode(nativeNode);
    }
    return nativeNode[NG_DEBUG_PROPERTY];
  }
  return null;
}

export { AFTER_RENDER_PHASES, ANIMATIONS_DISABLED, APP_BOOTSTRAP_LISTENER, APP_INITIALIZER, AcxChangeDetectionStrategy, AcxViewEncapsulation, AfterRenderImpl, AfterRenderManager, AfterRenderSequence, ApplicationInitStatus, ApplicationRef, Attribute, COMPILER_OPTIONS, CONTAINERS, CUSTOM_ELEMENTS_SCHEMA, ChainedInjector, ChangeDetectionSchedulerImpl, ChangeDetectionStrategy, Compiler, CompilerFactory, Component, ComponentFactory, ComponentRef$1 as ComponentRef, ComponentRef as ComponentRef$1, Console, ControlFlowBlockType, DEFAULT_CURRENCY_CODE, DEFAULT_LOCALE_ID, DEFER_BLOCK_CONFIG, DEFER_BLOCK_DEPENDENCY_INTERCEPTOR, DEFER_BLOCK_ID, DEFER_BLOCK_SSR_ID_ATTRIBUTE, DEFER_BLOCK_STATE$1 as DEFER_BLOCK_STATE, DEFER_BLOCK_STATE as DEFER_BLOCK_STATE$1, DEFER_HYDRATE_TRIGGERS, DEFER_PARENT_BLOCK_ID, DEHYDRATED_BLOCK_REGISTRY, DISCONNECTED_NODES, DebugElement, DebugEventListener, DebugNode, DeferBlockBehavior, DeferBlockState, Directive, ELEMENT_CONTAINERS, EVENT_REPLAY_ENABLED_DEFAULT, EVENT_REPLAY_QUEUE, ElementRef, EnvironmentNgModuleRefAdapter, Host, HostBinding, HostListener, HydrationStatus, I18N_DATA, IDLE_SERVICE, INCREMENTAL_HYDRATION_BOOTSTRAP, INPUT_SIGNAL_NODE, IS_ENABLED_BLOCKING_INITIAL_NAVIGATION, IS_EVENT_REPLAY_ENABLED, IS_HYDRATION_DOM_REUSE_ENABLED, IS_I18N_HYDRATION_ENABLED, IS_INCREMENTAL_HYDRATION_ENABLED, Inject, Injectable, Input, JSACTION_BLOCK_ELEMENT_MAP, JSACTION_EVENT_CONTRACT, LContext, LOCALE_ID, LocaleDataIndex, MAX_ANIMATION_TIMEOUT, MULTIPLIER, MissingTranslationStrategy, NGH_ATTR_NAME, NGH_DATA_KEY, NGH_DEFER_BLOCKS_KEY, NODES, NOOP_AFTER_RENDER_REF, NOT_FOUND_CHECK_ONLY_ELEMENT_INJECTOR, NO_CHANGE, NO_ERRORS_SCHEMA, NUM_ROOT_NODES, NgModule, NgModuleFactory, NgModuleFactory$1, NgModuleRef, NgModuleRef$1, NodeInjector, Optional, Output, PRESERVE_HOST_CONTENT, Pipe, ProfilerEvent, QueryList, REQUIRED_UNSET_VALUE, ReflectionCapabilities, Renderer2, RendererFactory2, RendererStyleFlags2, SHARED_STYLES_HOST, SKIP_HYDRATION_ATTR_NAME, SSR_CONTENT_INTEGRITY_MARKER, Sanitizer, Self, Service, SimpleChange, SkipSelf, TEMPLATES, TEMPLATE_ID, TESTABILITY, TESTABILITY_GETTER, TRANSLATIONS, TRANSLATIONS_FORMAT, TemplateRef, Testability, TestabilityRegistry, TimerScheduler, TracingAction, TracingService, Type, USE_PENDING_TASKS, UseExhaustiveCheckNoChanges, ViewContainerRef, ViewEncapsulation, ViewRef, _sanitizeHtml, _sanitizeUrl, afterEveryRender, afterNextRender, allLeavingAnimations, allowSanitizationBypassAndThrow, angularCoreEnv, asNativeElements, assertComponentDef, assertStandaloneComponentType, bypassSanitizationTrustHtml, bypassSanitizationTrustResourceUrl, bypassSanitizationTrustScript, bypassSanitizationTrustStyle, bypassSanitizationTrustUrl, calcPathForNode, checkNoChangesInternal, cleanupDehydratedViews, clearResolutionOfComponentResourcesQueue, collectNativeNodes, collectNativeNodesInLContainer, compileComponent, compileDirective, compileNgModule, compileNgModuleDefs, compilePipe, convertHydrateTriggersToJsAction, countBlocksSkippedByHydration, createDehydratedBlockRegistry, createEnvironmentInjector, createMultiResultQuerySignalFn, createNgModule, createNgModuleRefWithProviders, createSingleResultOptionalQuerySignalFn, createSingleResultRequiredQuerySignalFn, depsTracker, describeDomNode, devModeEqual, enableApplyRootElementTransformImpl, enableClaimDehydratedIcuCaseImpl, enableFindMatchingDehydratedViewImpl, enableLocateOrCreateContainerAnchorImpl, enableLocateOrCreateContainerRefImpl, enableLocateOrCreateElementContainerNodeImpl, enableLocateOrCreateElementNodeImpl, enableLocateOrCreateI18nNodeImpl, enableLocateOrCreateTextNodeImpl, enablePrepareI18nBlockForHydrationImpl, enableProfiling, enableRetrieveHydrationInfoImpl, enableStashEventListenerImpl, findLocaleData, flushModuleScopingQueueAsMuchAsPossible, generateStandaloneInDeclarationsError, getAsyncClassMetadataFn, getClosestComponentName, getCompilerFacade, getComponentInstanceDeepLinkId, getDebugNode, getDeferBlocks, getDirectives, getDocument, getHostElement, getInjector, getInjectorMetadata, getInjectorProviders, getLContext, getLDeferBlockDetails, getLNodeForHydration, getLocaleCurrencyCode, getLocalePluralCase, getNodeInjectorTNode, getOrComputeI18nChildren, getRegisteredNgModuleType, getSanitizationBypassType, getSignalGraph, getTDeferBlockDetails, getTransferState, inferTagNameFromDefinition, inputBinding, invokeListeners, isComponentDefPendingResolution, isComponentResourceResolutionQueueEmpty, isDeferBlock, isDetachedByI18n, isDisconnectedNode, isI18nHydrationEnabled, isI18nHydrationSupportEnabled, isInSkipHydrationBlock, isIncrementalHydrationEnabled, isJsObject, isLetDeclaration, isListLikeIterable, isNgModule, isPromise, isSubscribable, isTNodeShape, isViewDirty, iterateListLike, makePropDecorator, markForRefresh, noSideEffects, optionsReducer, outputBinding, patchComponentDefWithScope, performanceMarkFeature, processTextNodeBeforeSerialization, profiler, provideAppInitializer, provideIdleServiceWith, provideNgReflectAttributes, provideZonelessChangeDetection, provideZonelessChangeDetectionInternal, publishDefaultGlobalUtils, publishNonCoreGlobalUtil, publishSignalConfiguration, readHydrationInfo, registerLocaleData, registerNgModuleType, remove, removeListeners, renderDeferBlockState, resetCompiledComponents, resetIncrementalHydrationEnabledWarnedForTests, resetIncrementalHydrationRuntimeForTests, resetJitOptions, resolveComponentResources, restoreComponentResolutionQueue, runIncrementalHydrationBootstrap, setAllowDuplicateNgModuleIdsForTest, setClassMetadata, setClassMetadataAsync, setDocument, setIsI18nHydrationSupportEnabled, setJSActionAttributes, setJitOptions, setLocaleId, setStashFn, setTestabilityGetter, sharedMapFunction, sharedStashFunction, transitiveScopesFor, triggerHydrationFromBlockName, triggerResourceLoading, trySerializeI18nBlock, twoWayBinding, unregisterAllLocaleData, unsupportedProjectionOfDomNodes, unwrapSafeValue, validateMatchingNode, validateNodeExists, verifySsrContentsIntegrity, walkLViewDirectives, ɵgetUnknownElementStrictMode, ɵgetUnknownPropertyStrictMode, ɵsetClassDebugInfo, ɵsetUnknownElementStrictMode, ɵsetUnknownPropertyStrictMode, ɵɵControlFeature, ɵɵExternalStylesFeature, ɵɵHostDirectivesFeature, ɵɵInheritDefinitionFeature, ɵɵNgOnChangesFeature, ɵɵProvidersFeature, ɵɵadvance, ɵɵanimateEnter, ɵɵanimateEnterListener, ɵɵanimateLeave, ɵɵanimateLeaveListener, ɵɵariaProperty, ɵɵarrowFunction, ɵɵattachSourceLocations, ɵɵattribute, ɵɵboundaryCreate, ɵɵboundaryUpdate, ɵɵclassMap, ɵɵclassProp, ɵɵcomponentInstance, ɵɵconditional, ɵɵconditionalBranchCreate, ɵɵconditionalCreate, ɵɵcontentQuery, ɵɵcontentQuerySignal, ɵɵcontrol, ɵɵcontrolCreate, ɵɵdeclareLet, ɵɵdefer, ɵɵdeferEnableTimerScheduling, ɵɵdeferHydrateNever, ɵɵdeferHydrateOnHover, ɵɵdeferHydrateOnIdle, ɵɵdeferHydrateOnImmediate, ɵɵdeferHydrateOnInteraction, ɵɵdeferHydrateOnTimer, ɵɵdeferHydrateOnViewport, ɵɵdeferHydrateWhen, ɵɵdeferOnHover, ɵɵdeferOnIdle, ɵɵdeferOnImmediate, ɵɵdeferOnInteraction, ɵɵdeferOnTimer, ɵɵdeferOnViewport, ɵɵdeferPrefetchOnHover, ɵɵdeferPrefetchOnIdle, ɵɵdeferPrefetchOnImmediate, ɵɵdeferPrefetchOnInteraction, ɵɵdeferPrefetchOnTimer, ɵɵdeferPrefetchOnViewport, ɵɵdeferPrefetchWhen, ɵɵdeferWhen, ɵɵdefineComponent, ɵɵdefineDirective, ɵɵdefineNgModule, ɵɵdefinePipe, ɵɵdefineService, ɵɵdirectiveInject, ɵɵdomElement, ɵɵdomElementContainer, ɵɵdomElementContainerEnd, ɵɵdomElementContainerStart, ɵɵdomElementEnd, ɵɵdomElementStart, ɵɵdomListener, ɵɵdomProperty, ɵɵdomTemplate, ɵɵelement, ɵɵelementContainer, ɵɵelementContainerEnd, ɵɵelementContainerStart, ɵɵelementEnd, ɵɵelementStart, ɵɵenableIncrementalHydrationRuntime, ɵɵforeignComponent, ɵɵforeignContent, ɵɵforeignContentFn, ɵɵgetBoundary, ɵɵgetComponentDepsFactory, ɵɵgetCurrentView, ɵɵgetInheritedFactory, ɵɵgetReplaceMetadataURL, ɵɵi18n, ɵɵi18nApply, ɵɵi18nAttributes, ɵɵi18nEnd, ɵɵi18nExp, ɵɵi18nPostprocess, ɵɵi18nStart, ɵɵinjectAttribute, ɵɵinterpolate, ɵɵinterpolate1, ɵɵinterpolate2, ɵɵinterpolate3, ɵɵinterpolate4, ɵɵinterpolate5, ɵɵinterpolate6, ɵɵinterpolate7, ɵɵinterpolate8, ɵɵinterpolateV, ɵɵinvalidFactory, ɵɵlistener, ɵɵloadQuery, ɵɵnextContext, ɵɵpipe, ɵɵpipeBind1, ɵɵpipeBind2, ɵɵpipeBind3, ɵɵpipeBind4, ɵɵpipeBindV, ɵɵprojection, ɵɵprojectionDef, ɵɵproperty, ɵɵpureFunction0, ɵɵpureFunction1, ɵɵpureFunction2, ɵɵpureFunction3, ɵɵpureFunction4, ɵɵpureFunction5, ɵɵpureFunction6, ɵɵpureFunction7, ɵɵpureFunction8, ɵɵpureFunctionV, ɵɵqueryAdvance, ɵɵqueryRefresh, ɵɵreadContextLet, ɵɵreference, ɵɵrepeater, ɵɵrepeaterCreate, ɵɵrepeaterTrackByIdentity, ɵɵrepeaterTrackByIndex, ɵɵreplaceMetadata, ɵɵresolveBody, ɵɵresolveDocument, ɵɵresolveWindow, ɵɵsanitizeHtml, ɵɵsanitizeResourceUrl, ɵɵsanitizeScript, ɵɵsanitizeStyle, ɵɵsanitizeUrl, ɵɵsanitizeUrlOrResourceUrl, ɵɵsetComponentScope, ɵɵsetNgModuleScope, ɵɵstoreLet, ɵɵstyleMap, ɵɵstyleProp, ɵɵsyntheticHostListener, ɵɵsyntheticHostProperty, ɵɵtemplate, ɵɵtemplateRefExtractor, ɵɵtext, ɵɵtextInterpolate, ɵɵtextInterpolate1, ɵɵtextInterpolate2, ɵɵtextInterpolate3, ɵɵtextInterpolate4, ɵɵtextInterpolate5, ɵɵtextInterpolate6, ɵɵtextInterpolate7, ɵɵtextInterpolate8, ɵɵtextInterpolateV, ɵɵtrustConstantHtml, ɵɵtrustConstantResourceUrl, ɵɵtwoWayBindingSet, ɵɵtwoWayListener, ɵɵtwoWayProperty, ɵɵvalidateAttribute, ɵɵviewQuery, ɵɵviewQuerySignal };
//# sourceMappingURL=_debug_node-chunk.mjs.map
