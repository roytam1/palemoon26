/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "mozilla/dom/Element.h"
#include "mozilla/dom/HTMLMediaElement.h"
#include "mozilla/dom/HTMLTrackElement.h"
#include "mozilla/dom/HTMLTrackElementBinding.h"
#include "mozilla/dom/HTMLUnknownElement.h"
#include "WebVTTLoadListener.h"
#include "nsAttrValueInlines.h"
#include "nsCOMPtr.h"
#include "nsContentPolicyUtils.h"
#include "nsContentUtils.h"
#include "nsCycleCollectionParticipant.h"
#include "nsGenericHTMLElement.h"
#include "nsGkAtoms.h"
#include "nsIAsyncVerifyRedirectCallback.h"
#include "nsICachingChannel.h"
#include "nsIChannelEventSink.h"
#include "nsIChannelPolicy.h"
#include "nsIContentPolicy.h"
#include "nsIContentSecurityPolicy.h"
#include "nsIDocument.h"
#include "nsIDOMEventTarget.h"
#include "nsIDOMHTMLMediaElement.h"
#include "nsIFrame.h"
#include "nsIHttpChannel.h"
#include "nsIInterfaceRequestor.h"
#include "nsILoadGroup.h"
#include "nsIObserver.h"
#include "nsIStreamListener.h"
#include "nsISupportsImpl.h"
#include "nsMappedAttributes.h"
#include "nsNetUtil.h"
#include "nsRuleData.h"
#include "nsStyleConsts.h"
#include "nsThreadUtils.h"
#include "nsVideoFrame.h"

#ifdef PR_LOGGING
static PRLogModuleInfo* gTrackElementLog;
#define LOG(type, msg) PR_LOG(gTrackElementLog, type, msg)
#else
#define LOG(type, msg)
#endif

// Replace the usual NS_IMPL_NS_NEW_HTML_ELEMENT(Track) so
// we can return an UnknownElement instead when pref'd off.
nsGenericHTMLElement*
NS_NewHTMLTrackElement(already_AddRefed<nsINodeInfo> aNodeInfo,
                       mozilla::dom::FromParser aFromParser)
{
  if (!mozilla::dom::HTMLTrackElement::IsWebVTTEnabled()) {
    return mozilla::dom::NewHTMLElementHelper::Create<nsHTMLUnknownElement,
           mozilla::dom::HTMLUnknownElement>(aNodeInfo);
  }

  return mozilla::dom::NewHTMLElementHelper::Create<nsHTMLTrackElement,
         mozilla::dom::HTMLTrackElement>(aNodeInfo);
}

namespace mozilla {
namespace dom {

/** HTMLTrackElement */
HTMLTrackElement::HTMLTrackElement(already_AddRefed<nsINodeInfo> aNodeInfo)
  : nsGenericHTMLElement(aNodeInfo)
  , mReadyState(NONE)
{
#ifdef PR_LOGGING
  if (!gTrackElementLog) {
    gTrackElementLog = PR_NewLogModule("nsTrackElement");
  }
#endif

  SetIsDOMBinding();
}

HTMLTrackElement::~HTMLTrackElement()
{
}

NS_IMPL_ELEMENT_CLONE(HTMLTrackElement)

NS_IMPL_ADDREF_INHERITED(HTMLTrackElement, Element)
NS_IMPL_RELEASE_INHERITED(HTMLTrackElement, Element)

NS_IMPL_CYCLE_COLLECTION_INHERITED_4(HTMLTrackElement, nsGenericHTMLElement,
                                     mTrack, mChannel, mMediaParent,
                                     mLoadListener)

NS_INTERFACE_MAP_BEGIN_CYCLE_COLLECTION_INHERITED(HTMLTrackElement)
  NS_HTML_CONTENT_INTERFACES(nsGenericHTMLElement)
NS_ELEMENT_INTERFACE_MAP_END

void
HTMLTrackElement::OnChannelRedirect(nsIChannel* aChannel,
                                    nsIChannel* aNewChannel,
                                    uint32_t aFlags)
{
  NS_ASSERTION(aChannel == mChannel, "Channels should match!");
  mChannel = aNewChannel;
}

JSObject*
HTMLTrackElement::WrapNode(JSContext* aCx, JS::Handle<JSObject*> aScope)
{
  return HTMLTrackElementBinding::Wrap(aCx, aScope, this);
}

bool
HTMLTrackElement::IsWebVTTEnabled()
{
  // Our callee does not use its arguments.
  return HTMLTrackElementBinding::ConstructorEnabled(nullptr, JS::NullPtr());
}

TextTrack*
HTMLTrackElement::Track()
{
  if (!mTrack) {
    // We're expected to always have an internal TextTrack so create
    // an empty object to return if we don't already have one.
    mTrack = new TextTrack(OwnerDoc()->GetParentObject());
  }

  return mTrack;
}

void
HTMLTrackElement::CreateTextTrack()
{
  nsString label, srcLang;
  GetSrclang(srcLang);
  GetLabel(label);
  mTrack = new TextTrack(OwnerDoc()->GetParentObject(), Kind(), label, srcLang);

  if (mMediaParent) {
    mMediaParent->AddTextTrack(mTrack);
  }
}

TextTrackKind
HTMLTrackElement::Kind() const
{
  const nsAttrValue* value = GetParsedAttr(nsGkAtoms::kind);
  if (!value) {
    return TextTrackKind::Subtitles;
  }
  return static_cast<TextTrackKind>(value->GetEnumValue());
}

static EnumEntry
StringFromKind(TextTrackKind aKind)
{
  return TextTrackKindValues::strings[static_cast<int>(aKind)];
}

void
HTMLTrackElement::SetKind(TextTrackKind aKind, ErrorResult& aError)
{
  const EnumEntry& string = StringFromKind(aKind);
  nsAutoString kind;

  kind.AssignASCII(string.value, string.length);
  SetHTMLAttr(nsGkAtoms::kind, kind, aError);
}

bool
HTMLTrackElement::ParseAttribute(int32_t aNamespaceID,
                                 nsIAtom* aAttribute,
                                 const nsAString& aValue,
                                 nsAttrValue& aResult)
{
  // Map html attribute string values to TextTrackKind enums.
  static const nsAttrValue::EnumTable kKindTable[] = {
    { "subtitles", static_cast<int16_t>(TextTrackKind::Subtitles) },
    { "captions", static_cast<int16_t>(TextTrackKind::Captions) },
    { "descriptions", static_cast<int16_t>(TextTrackKind::Descriptions) },
    { "chapters", static_cast<int16_t>(TextTrackKind::Chapters) },
    { "metadata", static_cast<int16_t>(TextTrackKind::Metadata) },
    { 0 }
  };

  if (aNamespaceID == kNameSpaceID_None && aAttribute == nsGkAtoms::kind) {
    // Case-insensitive lookup, with the first element as the default.
    return aResult.ParseEnumValue(aValue, kKindTable, false, kKindTable);
  }

  // Otherwise call the generic implementation.
  return nsGenericHTMLElement::ParseAttribute(aNamespaceID,
                                              aAttribute,
                                              aValue,
                                              aResult);
}

void
HTMLTrackElement::LoadResource()
{
  // Find our 'src' url
  nsAutoString src;
  if (!GetAttr(kNameSpaceID_None, nsGkAtoms::src, src)) {
    return;
  }

  nsCOMPtr<nsIURI> uri;
  nsresult rv = NewURIFromString(src, getter_AddRefs(uri));
  NS_ENSURE_TRUE_VOID(NS_SUCCEEDED(rv));
  LOG(PR_LOG_ALWAYS, ("%p Trying to load from src=%s", this,
      NS_ConvertUTF16toUTF8(src).get()));

  if (mChannel) {
    mChannel->Cancel(NS_BINDING_ABORTED);
    mChannel = nullptr;
  }

  rv = nsContentUtils::GetSecurityManager()->
    CheckLoadURIWithPrincipal(NodePrincipal(), uri,
                              nsIScriptSecurityManager::STANDARD);
  NS_ENSURE_TRUE_VOID(NS_SUCCEEDED(rv));

  int16_t shouldLoad = nsIContentPolicy::ACCEPT;
  rv = NS_CheckContentLoadPolicy(nsIContentPolicy::TYPE_MEDIA,
                                 uri,
                                 NodePrincipal(),
                                 static_cast<nsGenericHTMLElement*>(this),
                                 NS_LITERAL_CSTRING("text/vtt"), // mime type
                                 nullptr, // extra
                                 &shouldLoad,
                                 nsContentUtils::GetContentPolicy(),
                                 nsContentUtils::GetSecurityManager());
  NS_ENSURE_TRUE_VOID(NS_SUCCEEDED(rv));
  if (NS_CP_REJECTED(shouldLoad)) {
    return;
  }

  CreateTextTrack();

  // Check for a Content Security Policy to pass down to the channel
  // created to load the media content.
  nsCOMPtr<nsIChannelPolicy> channelPolicy;
  nsCOMPtr<nsIContentSecurityPolicy> csp;
  rv = NodePrincipal()->GetCsp(getter_AddRefs(csp));
  NS_ENSURE_TRUE_VOID(NS_SUCCEEDED(rv));
  if (csp) {
    channelPolicy = do_CreateInstance("@mozilla.org/nschannelpolicy;1");
    if (!channelPolicy) {
      return;
    }
    channelPolicy->SetContentSecurityPolicy(csp);
    channelPolicy->SetLoadType(nsIContentPolicy::TYPE_MEDIA);
  }
  nsCOMPtr<nsIChannel> channel;
  nsCOMPtr<nsILoadGroup> loadGroup = OwnerDoc()->GetDocumentLoadGroup();
  rv = NS_NewChannel(getter_AddRefs(channel),
                     uri,
                     nullptr,
                     loadGroup,
                     nullptr,
                     nsIRequest::LOAD_NORMAL,
                     channelPolicy);
  NS_ENSURE_TRUE_VOID(NS_SUCCEEDED(rv));

  mLoadListener = new WebVTTLoadListener(this);
  rv = mLoadListener->LoadResource();
  NS_ENSURE_TRUE_VOID(NS_SUCCEEDED(rv));
  channel->SetNotificationCallbacks(mLoadListener);

  LOG(PR_LOG_DEBUG, ("opening webvtt channel"));
  rv = channel->AsyncOpen(mLoadListener, nullptr);
  NS_ENSURE_TRUE_VOID(NS_SUCCEEDED(rv));

  mChannel = channel;
}

nsresult
HTMLTrackElement::BindToTree(nsIDocument* aDocument,
                             nsIContent* aParent,
                             nsIContent* aBindingParent,
                             bool aCompileEventHandlers)
{
  nsresult rv = nsGenericHTMLElement::BindToTree(aDocument,
                                                 aParent,
                                                 aBindingParent,
                                                 aCompileEventHandlers);
  NS_ENSURE_SUCCESS(rv, rv);

  if (!aDocument) {
    return NS_OK;
  }

  LOG(PR_LOG_DEBUG, ("Track Element bound to tree."));
  if (!aParent || !aParent->IsNodeOfType(nsINode::eMEDIA)) {
    return NS_OK;
  }

  // Store our parent so we can look up its frame for display.
  if (!mMediaParent) {
    mMediaParent = static_cast<HTMLMediaElement*>(aParent);

    HTMLMediaElement* media = static_cast<HTMLMediaElement*>(aParent);
    // TODO: separate notification for 'alternate' tracks?
    media->NotifyAddedSource();
    LOG(PR_LOG_DEBUG, ("Track element sent notification to parent."));

    nsContentUtils::AddScriptRunner(
      NS_NewRunnableMethod(this, &HTMLTrackElement::LoadResource));
  }

  return NS_OK;
}

void
HTMLTrackElement::UnbindFromTree(bool aDeep, bool aNullParent)
{
  if (mMediaParent && aNullParent) {
    mMediaParent = nullptr;
  }

  nsGenericHTMLElement::UnbindFromTree(aDeep, aNullParent);
}

} // namespace dom
} // namespace mozilla
