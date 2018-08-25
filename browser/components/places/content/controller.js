/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

Components.utils.import("resource://gre/modules/XPCOMUtils.jsm");
Components.utils.import("resource://gre/modules/ForgetAboutSite.jsm");
XPCOMUtils.defineLazyModuleGetter(this, "NetUtil",
                                  "resource://gre/modules/NetUtil.jsm");

// XXXmano: we should move most/all of these constants to PlacesUtils
const ORGANIZER_ROOT_BOOKMARKS = "place:folder=BOOKMARKS_MENU&excludeItems=1&queryType=1";

// No change to the view, preserve current selection
const RELOAD_ACTION_NOTHING = 0;
// Inserting items new to the view, select the inserted rows
const RELOAD_ACTION_INSERT = 1;
// Removing items from the view, select the first item after the last selected
const RELOAD_ACTION_REMOVE = 2;
// Moving items within a view, don't treat the dropped items as additional
// rows.
const RELOAD_ACTION_MOVE = 3;

// When removing a bunch of pages we split them in chunks to give some breath
// to the main-thread.
const REMOVE_PAGES_CHUNKLEN = 300;

/**
 * Represents an insertion point within a container where we can insert
 * items.
 * @param   aItemId
 *          The identifier of the parent container
 * @param   aIndex
 *          The index within the container where we should insert
 * @param   aOrientation
 *          The orientation of the insertion. NOTE: the adjustments to the
 *          insertion point to accommodate the orientation should be done by
 *          the person who constructs the IP, not the user. The orientation
 *          is provided for informational purposes only!
 * @param   [optional] aIsTag
 *          Indicates if parent container is a tag
 * @param   [optional] aDropNearItemId
 *          When defined we will calculate index based on this itemId
 * @constructor
 */
function InsertionPoint(aItemId, aIndex, aOrientation, aIsTag,
                        aDropNearItemId) {
  this.itemId = aItemId;
  this._index = aIndex;
  this.orientation = aOrientation;
  this.isTag = aIsTag;
  this.dropNearItemId = aDropNearItemId;
}

InsertionPoint.prototype = {
  set index(val) {
    return this._index = val;
  },

  get index() {
    if (this.dropNearItemId > 0) {
      // If dropNearItemId is set up we must calculate the real index of
      // the item near which we will drop.
      var index = PlacesUtils.bookmarks.getItemIndex(this.dropNearItemId);
      return this.orientation == Ci.nsITreeView.DROP_BEFORE ? index : index + 1;
    }
    return this._index;
  }
};

/**
 * Places Controller
 */

function PlacesController(aView) {
  this._view = aView;
  XPCOMUtils.defineLazyServiceGetter(this, "clipboard",
                                     "@mozilla.org/widget/clipboard;1",
                                     "nsIClipboard");
  XPCOMUtils.defineLazyGetter(this, "profileName", function () {
    return Services.dirsvc.get("ProfD", Ci.nsIFile).leafName;
  });

  this._cachedLivemarkInfoObjects = new Map();
}

PlacesController.prototype = {
  /**
   * The places view.
   */
  _view: null,

  QueryInterface: XPCOMUtils.generateQI([
    Ci.nsIClipboardOwner
  ]),

  // nsIClipboardOwner
  LosingOwnership: function PC_LosingOwnership (aXferable) {
    this.cutNodes = [];
  },

  terminate: function PC_terminate() {
    this._releaseClipboardOwnership();
  },

  supportsCommand: function PC_supportsCommand(aCommand) {
    // Non-Places specific commands that we also support
    switch (aCommand) {
    case "cmd_undo":
    case "cmd_redo":
    case "cmd_cut":
    case "cmd_copy":
    case "cmd_paste":
    case "cmd_delete":
    case "cmd_selectAll":
      return true;
    }

    // All other Places Commands are prefixed with "placesCmd_" ... this
    // filters out other commands that we do _not_ support (see 329587).
    const CMD_PREFIX = "placesCmd_";
    return (aCommand.substr(0, CMD_PREFIX.length) == CMD_PREFIX);
  },

  isCommandEnabled: function PC_isCommandEnabled(aCommand) {
    switch (aCommand) {
    case "cmd_undo":
      return PlacesUtils.transactionManager.numberOfUndoItems > 0;
    case "cmd_redo":
      return PlacesUtils.transactionManager.numberOfRedoItems > 0;
    case "cmd_cut":
    case "placesCmd_cut":
      var nodes = this._view.selectedNodes;
      // If selection includes history nodes there's no reason to allow cut.
      for (var i = 0; i < nodes.length; i++) {
        if (nodes[i].itemId == -1)
          return false;
      }
      // Otherwise fallback to cmd_delete check.
    case "cmd_delete":
    case "placesCmd_delete":
    case "placesCmd_deleteDataHost":
      return this._hasRemovableSelection(false);
    case "placesCmd_moveBookmarks":
      return this._hasRemovableSelection(true);
    case "cmd_copy":
    case "placesCmd_copy":
      return this._view.hasSelection;
    case "cmd_paste":
    case "placesCmd_paste":
      return this._canInsert(true) && this._isClipboardDataPasteable();
    case "cmd_selectAll":
      if (this._view.selType != "single") {
        let rootNode = this._view.result.root;
        if (rootNode.containerOpen && rootNode.childCount > 0)
          return true;
      }
      return false;
    case "placesCmd_open":
    case "placesCmd_open:window":
    case "placesCmd_open:tab":
      var selectedNode = this._view.selectedNode;
      return selectedNode && PlacesUtils.nodeIsURI(selectedNode);
    case "placesCmd_new:folder":
    case "placesCmd_new:livemark":
      return this._canInsert();
    case "placesCmd_new:bookmark":
      return this._canInsert();
    case "placesCmd_new:separator":
      return this._canInsert() &&
             !PlacesUtils.asQuery(this._view.result.root).queryOptions.excludeItems &&
             this._view.result.sortingMode ==
                 Ci.nsINavHistoryQueryOptions.SORT_BY_NONE;
    case "placesCmd_show:info":
      var selectedNode = this._view.selectedNode;
      return selectedNode && PlacesUtils.getConcreteItemId(selectedNode) != -1
    case "placesCmd_reload":
      // Livemark containers
      var selectedNode = this._view.selectedNode;
      return selectedNode && this.hasCachedLivemarkInfo(selectedNode);
    case "placesCmd_sortBy:name":
      var selectedNode = this._view.selectedNode;
      return selectedNode &&
             PlacesUtils.nodeIsFolder(selectedNode) &&
             !PlacesUtils.nodeIsReadOnly(selectedNode) &&
             this._view.result.sortingMode ==
                 Ci.nsINavHistoryQueryOptions.SORT_BY_NONE;
    case "placesCmd_createBookmark":
      var node = this._view.selectedNode;
      return node && PlacesUtils.nodeIsURI(node) && node.itemId == -1;
    case "placesCmd_openParentFolder":
      return true;
    default:
      return false;
    }
  },

  doCommand: function PC_doCommand(aCommand) {
    switch (aCommand) {
    case "cmd_undo":
      PlacesUtils.transactionManager.undoTransaction();
      break;
    case "cmd_redo":
      PlacesUtils.transactionManager.redoTransaction();
      break;
    case "cmd_cut":
    case "placesCmd_cut":
      this.cut();
      break;
    case "cmd_copy":
    case "placesCmd_copy":
      this.copy();
      break;
    case "cmd_paste":
    case "placesCmd_paste":
      this.paste();
      break;
    case "cmd_delete":
    case "placesCmd_delete":
      this.remove("Remove Selection");
      break;
    case "placesCmd_deleteDataHost":
      var host;
      if (PlacesUtils.nodeIsHost(this._view.selectedNode)) {
        var queries = this._view.selectedNode.getQueries();
        host = queries[0].domain;
      }
      else
        host = NetUtil.newURI(this._view.selectedNode.uri).host;
      ForgetAboutSite.removeDataFromDomain(host);
      break;
    case "cmd_selectAll":
      this.selectAll();
      break;
    case "placesCmd_open":
      PlacesUIUtils.openNodeIn(this._view.selectedNode, "current", this._view);
      break;
    case "placesCmd_open:window":
      PlacesUIUtils.openNodeIn(this._view.selectedNode, "window", this._view);
      break;
    case "placesCmd_open:tab":
      PlacesUIUtils.openNodeIn(this._view.selectedNode, "tab", this._view);
      break;
    case "placesCmd_new:folder":
      this.newItem("folder");
      break;
    case "placesCmd_new:bookmark":
      this.newItem("bookmark");
      break;
    case "placesCmd_new:livemark":
      this.newItem("livemark");
      break;
    case "placesCmd_new:separator":
      this.newSeparator();
      break;
    case "placesCmd_show:info":
      this.showBookmarkPropertiesForSelection();
      break;
    case "placesCmd_moveBookmarks":
      this.moveSelectedBookmarks();
      break;
    case "placesCmd_reload":
      this.reloadSelectedLivemark();
      break;
    case "placesCmd_sortBy:name":
      this.sortFolderByName();
      break;
    case "placesCmd_createBookmark":
      let node = this._view.selectedNode;
      PlacesUIUtils.showBookmarkDialog({ action: "add"
                                       , type: "bookmark"
                                       , hiddenRows: [ "description"
                                                     , "keyword"
                                                     , "location"
                                                     , "loadInSidebar" ]
                                       , uri: NetUtil.newURI(node.uri)
                                       , title: node.title
                                       }, window.top);
      break;
    case "placesCmd_openParentFolder":
      this.openParentFolder();
      break;
    }
  },

  onEvent: function PC_onEvent(eventName) { },


  /**
   * Determine whether or not the selection can be removed, either by the
   * delete or cut operations based on whether or not any of its contents
   * are non-removable. We don't need to worry about recursion here since it
   * is a policy decision that a removable item not be placed inside a non-
   * removable item.
   * @param aIsMoveCommand
   *        True if the command for which this method is called only moves the
   *        selected items to another container, false otherwise.
   * @returns true if all nodes in the selection can be removed,
   *          false otherwise.
   */
  _hasRemovableSelection: function PC__hasRemovableSelection(aIsMoveCommand) {
    var ranges = this._view.removableSelectionRanges;
    if (!ranges.length)
      return false;

    var root = this._view.result.root;

    for (var j = 0; j < ranges.length; j++) {
      var nodes = ranges[j];
      for (var i = 0; i < nodes.length; ++i) {
        // Disallow removing the view's root node
        if (nodes[i] == root)
          return false;

        if (PlacesUtils.nodeIsFolder(nodes[i]) &&
            !PlacesControllerDragHelper.canMoveNode(nodes[i]))
          return false;

        // We don't call nodeIsReadOnly here, because nodeIsReadOnly means that
        // a node has children that cannot be edited, reordered or removed. Here,
        // we don't care if a node's children can't be reordered or edited, just
        // that they're removable. All history results have removable children
        // (based on the principle that any URL in the history table should be
        // removable), but some special bookmark folders may have non-removable
        // children, e.g. live bookmark folder children. It doesn't make sense
        // to delete a child of a live bookmark folder, since when the folder
        // refreshes, the child will return.
        var parent = nodes[i].parent || root;
        if (PlacesUtils.isReadonlyFolder(parent))
          return false;
      }
    }

    return true;
  },

  /**
   * Determines whether or not nodes can be inserted relative to the selection.
   */
  _canInsert: function PC__canInsert(isPaste) {
    var ip = this._view.insertionPoint;
    return ip != null && (isPaste || ip.isTag != true);
  },

  /**
   * Determines whether or not the root node for the view is selected
   */
  rootNodeIsSelected: function PC_rootNodeIsSelected() {
    var nodes = this._view.selectedNodes;
    var root = this._view.result.root;
    for (var i = 0; i < nodes.length; ++i) {
      if (nodes[i] == root)
        return true;
    }

    return false;
  },

  /**
   * Looks at the data on the clipboard to see if it is paste-able.
   * Paste-able data is:
   *   - in a format that the view can receive
   * @returns true if: - clipboard data is of a TYPE_X_MOZ_PLACE_* flavor,
                       - clipboard data is of type TEXT_UNICODE and
                         is a valid URI.
   */
  _isClipboardDataPasteable: function PC__isClipboardDataPasteable() {
    // if the clipboard contains TYPE_X_MOZ_PLACE_* data, it is definitely
    // pasteable, with no need to unwrap all the nodes.

    var flavors = PlacesControllerDragHelper.placesFlavors;
    var clipboard = this.clipboard;
    var hasPlacesData =
      clipboard.hasDataMatchingFlavors(flavors, flavors.length,
                                       Ci.nsIClipboard.kGlobalClipboard);
    if (hasPlacesData)
      return this._view.insertionPoint != null;

    // if the clipboard doesn't have TYPE_X_MOZ_PLACE_* data, we also allow
    // pasting of valid "text/unicode" and "text/x-moz-url" data
    var xferable = Cc["@mozilla.org/widget/transferable;1"].
                   createInstance(Ci.nsITransferable);
    xferable.init(null);

    xferable.addDataFlavor(PlacesUtils.TYPE_X_MOZ_URL);
    xferable.addDataFlavor(PlacesUtils.TYPE_UNICODE);
    clipboard.getData(xferable, Ci.nsIClipboard.kGlobalClipboard);

    try {
      // getAnyTransferData will throw if no data is available.
      var data = { }, type = { };
      xferable.getAnyTransferData(type, data, { });
      data = data.value.QueryInterface(Ci.nsISupportsString).data;
      if (type.value != PlacesUtils.TYPE_X_MOZ_URL &&
          type.value != PlacesUtils.TYPE_UNICODE)
        return false;

      // unwrapNodes() will throw if the data blob is malformed.
      var unwrappedNodes = PlacesUtils.unwrapNodes(data, type.value);
      return this._view.insertionPoint != null;
    }
    catch (e) {
      // getAnyTransferData or unwrapNodes failed
      return false;
    }
  },

  /**
   * Gathers information about the selected nodes according to the following
   * rules:
   *    "link"              node is a URI
   *    "bookmark"          node is a bookamrk
   *    "livemarkChild"     node is a child of a livemark
   *    "tagChild"          node is a child of a tag
   *    "folder"            node is a folder
   *    "query"             node is a query
   *    "separator"         node is a separator line
   *    "host"              node is a host
   *
   * @returns an array of objects corresponding the selected nodes. Each
   *          object has each of the properties above set if its corresponding
   *          node matches the rule. In addition, the annotations names for each
   *          node are set on its corresponding object as properties.
   * Notes:
   *   1) This can be slow, so don't call it anywhere performance critical!
   *   2) A single-object array corresponding the root node is returned if
   *      there's no selection.
   */
  _buildSelectionMetadata: function PC__buildSelectionMetadata() {
    var metadata = [];
    var root = this._view.result.root;
    var nodes = this._view.selectedNodes;
    if (nodes.length == 0)
      nodes.push(root); // See the second note above

    for (var i = 0; i < nodes.length; i++) {
      var nodeData = {};
      var node = nodes[i];
      var nodeType = node.type;
      var uri = null;

      // We don't use the nodeIs* methods here to avoid going through the type
      // property way too often
      switch (nodeType) {
        case Ci.nsINavHistoryResultNode.RESULT_TYPE_QUERY:
          nodeData["query"] = true;
          if (node.parent) {
            switch (PlacesUtils.asQuery(node.parent).queryOptions.resultType) {
              case Ci.nsINavHistoryQueryOptions.RESULTS_AS_SITE_QUERY:
                nodeData["host"] = true;
                break;
              case Ci.nsINavHistoryQueryOptions.RESULTS_AS_DATE_SITE_QUERY:
              case Ci.nsINavHistoryQueryOptions.RESULTS_AS_DATE_QUERY:
                nodeData["day"] = true;
                break;
            }
          }
          break;
        case Ci.nsINavHistoryResultNode.RESULT_TYPE_FOLDER:
        case Ci.nsINavHistoryResultNode.RESULT_TYPE_FOLDER_SHORTCUT:
          nodeData["folder"] = true;
          break;
        case Ci.nsINavHistoryResultNode.RESULT_TYPE_SEPARATOR:
          nodeData["separator"] = true;
          break;
        case Ci.nsINavHistoryResultNode.RESULT_TYPE_URI:
          nodeData["link"] = true;
          uri = NetUtil.newURI(node.uri);
          if (PlacesUtils.nodeIsBookmark(node)) {
            nodeData["bookmark"] = true;
            PlacesUtils.nodeIsTagQuery(node.parent)

            var parentNode = node.parent;
            if (parentNode) {
              if (PlacesUtils.nodeIsTagQuery(parentNode))
                nodeData["tagChild"] = true;
              else if (this.hasCachedLivemarkInfo(parentNode))
                nodeData["livemarkChild"] = true;
            }
          }
          break;
      }

      // annotations
      if (uri) {
        let names = PlacesUtils.annotations.getPageAnnotationNames(uri);
        for (let j = 0; j < names.length; ++j)
          nodeData[names[j]] = true;
      }

      // For items also include the item-specific annotations
      if (node.itemId != -1) {
        let names = PlacesUtils.annotations
                               .getItemAnnotationNames(node.itemId);
        for (let j = 0; j < names.length; ++j)
          nodeData[names[j]] = true;
      }
      metadata.push(nodeData);
    }

    return metadata;
  },

  /**
   * Determines if a context-menu item should be shown
   * @param   aMenuItem
   *          the context menu item
   * @param   aMetaData
   *          meta data about the selection
   * @returns true if the conditions (see buildContextMenu) are satisfied
   *          and the item can be displayed, false otherwise.
   */
  _shouldShowMenuItem: function PC__shouldShowMenuItem(aMenuItem, aMetaData) {
    var selectiontype = aMenuItem.getAttribute("selectiontype");
    if (selectiontype == "multiple" && aMetaData.length == 1)
      return false;
    if (selectiontype == "single" && aMetaData.length != 1)
      return false;

    var forceHideAttr = aMenuItem.getAttribute("forcehideselection");
    if (forceHideAttr) {
      var forceHideRules = forceHideAttr.split("|");
      for (let i = 0; i < aMetaData.length; ++i) {
        for (let j = 0; j < forceHideRules.length; ++j) {
          if (forceHideRules[j] in aMetaData[i])
            return false;
        }
      }
    }

    var selectionAttr = aMenuItem.getAttribute("selection");
    if (!selectionAttr) {
      return !aMenuItem.hidden;
    }

    if (selectionAttr == "any")
      return true;

    var showRules = selectionAttr.split("|");
    var anyMatched = false;
    function metaDataNodeMatches(metaDataNode, rules) {
      for (var i = 0; i < rules.length; i++) {
        if (rules[i] in metaDataNode)
          return true;
      }
      return false;
    }

    for (var i = 0; i < aMetaData.length; ++i) {
      if (metaDataNodeMatches(aMetaData[i], showRules))
        anyMatched = true;
      else
        return false;
    }
    return anyMatched;
  },

  /**
   * Detects information (meta-data rules) about the current selection in the
   * view (see _buildSelectionMetadata) and sets the visibility state for each
   * of the menu-items in the given popup with the following rules applied:
   *  1) The "selectiontype" attribute may be set on a menu-item to "single"
   *     if the menu-item should be visible only if there is a single node
   *     selected, or to "multiple" if the menu-item should be visible only if
   *     multiple nodes are selected. If the attribute is not set or if it is
   *     set to an invalid value, the menu-item may be visible for both types of
   *     selection.
   *  2) The "selection" attribute may be set on a menu-item to the various
   *     meta-data rules for which it may be visible. The rules should be
   *     separated with the | character.
   *  3) A menu-item may be visible only if at least one of the rules set in
   *     its selection attribute apply to each of the selected nodes in the
   *     view.
   *  4) The "forcehideselection" attribute may be set on a menu-item to rules
   *     for which it should be hidden. This attribute takes priority over the
   *     selection attribute. A menu-item would be hidden if at least one of the
   *     given rules apply to one of the selected nodes. The rules should be
   *     separated with the | character.
   *  5) The "hideifnoinsertionpoint" attribute may be set on a menu-item to
   *     true if it should be hidden when there's no insertion point
   *  6) The visibility state of a menu-item is unchanged if none of these
   *     attribute are set.
   *  7) These attributes should not be set on separators for which the
   *     visibility state is "auto-detected."
   *  8) The "hideifprivatebrowsing" attribute may be set on a menu-item to
   *     true if it should be hidden inside the private browsing mode
   * @param   aPopup
   *          The menupopup to build children into.
   * @return true if at least one item is visible, false otherwise.
   */
  buildContextMenu: function PC_buildContextMenu(aPopup) {
    var metadata = this._buildSelectionMetadata();
    var ip = this._view.insertionPoint;
    var noIp = !ip || ip.isTag;

    var separator = null;
    var visibleItemsBeforeSep = false;
    var anyVisible = false;
    for (var i = 0; i < aPopup.childNodes.length; ++i) {
      var item = aPopup.childNodes[i];
      if (item.localName != "menuseparator") {
        // We allow pasting into tag containers, so special case that.
        var hideIfNoIP = item.getAttribute("hideifnoinsertionpoint") == "true" &&
                         noIp && !(ip && ip.isTag && item.id == "placesContext_paste");
        // Show the "Open Containing Folder" menu-item only when the context is
        // in the Library or in the Sidebar, and only when there's no insertion
        // point.
        var hideParentFolderItem = item.id == "placesContext_openParentFolder" &&
                                   (!/tree/i.test(this._view.localName) || ip);
        item.hidden = hideIfNoIP || hideParentFolderItem ||
                      !this._shouldShowMenuItem(item, metadata);

        if (!item.hidden) {
          visibleItemsBeforeSep = true;
          anyVisible = true;

          // Show the separator above the menu-item if any
          if (separator) {
            separator.hidden = false;
            separator = null;
          }
        }
      }
      else { // menuseparator
        // Initially hide it. It will be unhidden if there will be at least one
        // visible menu-item above and below it.
        item.hidden = true;

        // We won't show the separator at all if no items are visible above it
        if (visibleItemsBeforeSep)
          separator = item;

        // New separator, count again:
        visibleItemsBeforeSep = false;
      }
    }

    // Set Open Folder/Links In Tabs items enabled state if they're visible
    if (anyVisible) {
      var openContainerInTabsItem = document.getElementById("placesContext_openContainer:tabs");
      if (!openContainerInTabsItem.hidden && this._view.selectedNode &&
          PlacesUtils.nodeIsContainer(this._view.selectedNode)) {
        openContainerInTabsItem.disabled =
          !PlacesUtils.hasChildURIs(this._view.selectedNode);
      }
      else {
        // see selectiontype rule in the overlay
        var openLinksInTabsItem = document.getElementById("placesContext_openLinks:tabs");
        openLinksInTabsItem.disabled = openLinksInTabsItem.hidden;
      }
    }

    return anyVisible;
  },

  /**
   * Select all links in the current view.
   */
  selectAll: function PC_selectAll() {
    this._view.selectAll();
  },

  /**
   * Opens the bookmark properties for the selected URI Node.
   */
  showBookmarkPropertiesForSelection:
  function PC_showBookmarkPropertiesForSelection() {
    var node = this._view.selectedNode;
    if (!node)
      return;

    var itemType = PlacesUtils.nodeIsFolder(node) ||
                   PlacesUtils.nodeIsTagQuery(node) ? "folder" : "bookmark";
    var concreteId = PlacesUtils.getConcreteItemId(node);
    var isRootItem = PlacesUtils.isRootItem(concreteId);
    var itemId = node.itemId;
    if (isRootItem || PlacesUtils.nodeIsTagQuery(node)) {
      // If this is a root or the Tags query we use the concrete itemId to catch
      // the correct title for the node.
      itemId = concreteId;
    }

    PlacesUIUtils.showBookmarkDialog({ action: "edit"
                                     , type: itemType
                                     , itemId: itemId
                                     , readOnly: isRootItem
                                     , hiddenRows: [ "folderPicker" ]
                                     }, window.top);
  },

  /**
   * This method can be run on a URI parameter to ensure that it didn't
   * receive a string instead of an nsIURI object.
   */
  _assertURINotString: function PC__assertURINotString(value) {
    NS_ASSERT((typeof(value) == "object") && !(value instanceof String),
           "This method should be passed a URI as a nsIURI object, not as a string.");
  },

  /**
   * Reloads the selected livemark if any.
   */
  reloadSelectedLivemark: function PC_reloadSelectedLivemark() {
    var selectedNode = this._view.selectedNode;
    if (selectedNode) {
      let itemId = selectedNode.itemId;
      PlacesUtils.livemarks.getLivemark(
        { id: itemId },
        (function(aStatus, aLivemark) {
          if (Components.isSuccessCode(aStatus)) {
            aLivemark.reload(true);
          }
        }).bind(this)
      );
    }
  },

  /**
   * Opens the links in the selected folder, or the selected links in new tabs.
   */
  openSelectionInTabs: function PC_openLinksInTabs(aEvent) {
    var node = this._view.selectedNode;
    if (node && PlacesUtils.nodeIsContainer(node))
      PlacesUIUtils.openContainerNodeInTabs(this._view.selectedNode, aEvent, this._view);
    else
      PlacesUIUtils.openURINodesInTabs(this._view.selectedNodes, aEvent, this._view);
  },

  /**
   * Shows the Add Bookmark UI for the current insertion point.
   *
   * @param aType
   *        the type of the new item (bookmark/livemark/folder)
   */
  newItem: function PC_newItem(aType) {
    let ip = this._view.insertionPoint;
    if (!ip)
      throw Cr.NS_ERROR_NOT_AVAILABLE;

    let performed =
      PlacesUIUtils.showBookmarkDialog({ action: "add"
                                       , type: aType
                                       , defaultInsertionPoint: ip
                                       , hiddenRows: [ "folderPicker" ]
                                       }, window.top);
    if (performed) {
      // Select the new item.
      let insertedNodeId = PlacesUtils.bookmarks
                                      .getIdForItemAt(ip.itemId, ip.index);
      this._view.selectItems([insertedNodeId], false);
    }
  },

  /**
   * Create a new Bookmark separator somewhere.
   */
  newSeparator: function PC_newSeparator() {
    var ip = this._view.insertionPoint;
    if (!ip)
      throw Cr.NS_ERROR_NOT_AVAILABLE;
    var txn = new PlacesCreateSeparatorTransaction(ip.itemId, ip.index);
    PlacesUtils.transactionManager.doTransaction(txn);
    // select the new item
    var insertedNodeId = PlacesUtils.bookmarks
                                    .getIdForItemAt(ip.itemId, ip.index);
    this._view.selectItems([insertedNodeId], false);
  },

  /**
   * Opens a dialog for moving the selected nodes.
   */
  moveSelectedBookmarks: function PC_moveBookmarks() {
    window.openDialog("chrome://browser/content/places/moveBookmarks.xul",
                      "", "chrome, modal",
                      this._view.selectedNodes);
  },

  /**
   * Sort the selected folder by name.
   */
  sortFolderByName: function PC_sortFolderByName() {
    var itemId = PlacesUtils.getConcreteItemId(this._view.selectedNode);
    var txn = new PlacesSortFolderByNameTransaction(itemId);
    PlacesUtils.transactionManager.doTransaction(txn);
  },

  /**
   * Open the parent folder for the selected bookmarks search result.
   */
  openParentFolder: function PC_openParentFolder() {
    var view;
    if (!document.popupNode) {
      view = document.commandDispatcher.focusedElement;
    } else {
      view = PlacesUIUtils.getViewForNode(document.popupNode); // XULElement
    }
    if (!view || view.getAttribute("type") != "places")
      return;
    var node = view.selectedNode; // nsINavHistoryResultNode
    var aItemId = node.itemId;
    var aFolderItemId = this.getParentFolderByItemId(aItemId);
    if (aFolderItemId)
      this.selectFolderByItemId(view, aFolderItemId, aItemId);
  },

  getParentFolderByItemId: function PC_getParentFolderByItemId(aItemId) {
    var bmsvc = Components.classes["@mozilla.org/browser/nav-bookmarks-service;1"].
                           getService(Components.interfaces.nsINavBookmarksService);
    var parentFolderId = bmsvc.getFolderIdForItem(aItemId);

    return parentFolderId;
  },

  selectItems2: function PC_selectItems2(view, aIDs) {
    var ids = aIDs; // Don't manipulate the caller's array.

    // Array of nodes found by findNodes which are to be selected
    var nodes = [];

    // Array of nodes found by findNodes which should be opened
    var nodesToOpen = [];

    // A set of URIs of container-nodes that were previously searched,
    // and thus shouldn't be searched again. This is empty at the initial
    // start of the recursion and gets filled in as the recursion
    // progresses.
    var nodesURIChecked = [];

    /**
     * Recursively search through a node's children for items
     * with the given IDs. When a matching item is found, remove its ID
     * from the IDs array, and add the found node to the nodes dictionary.
     *
     * NOTE: This method will leave open any node that had matching items
     * in its subtree.
     */
    function findNodes(node) {
      var foundOne = false;
      // See if node matches an ID we wanted; add to results.
      // For simple folder queries, check both itemId and the concrete
      // item id.
      var index = ids.indexOf(node.itemId);
      if (index == -1 &&
          node.type == Components.interfaces.nsINavHistoryResultNode.RESULT_TYPE_FOLDER_SHORTCUT) {
        index = ids.indexOf(PlacesUtils.asQuery(node).folderItemId); //xxx Bug 556739 3.7a5pre
      }

      if (index != -1) {
        nodes.push(node);
        foundOne = true;
        ids.splice(index, 1);
      }

      if (ids.length == 0 || !PlacesUtils.nodeIsContainer(node) ||
          nodesURIChecked.indexOf(node.uri) != -1)
        return foundOne;

      nodesURIChecked.push(node.uri);
      PlacesUtils.asContainer(node); // xxx Bug 556739 3.7a6pre

      // Remember the beginning state so that we can re-close
      // this node if we don't find any additional results here.
      var previousOpenness = node.containerOpen;
      node.containerOpen = true;
      for (var child = 0;  child < node.childCount && ids.length > 0;
           child++) {
        var childNode = node.getChild(child);
        var found = findNodes(childNode);
        if (!foundOne)
          foundOne = found;
      }

      // If we didn't find any additional matches in this node's
      // subtree, revert the node to its previous openness.
      if (foundOne)
        nodesToOpen.unshift(node);
      node.containerOpen = previousOpenness;
      return foundOne;
    } // findNodes

    // Disable notifications while looking for nodes.
    let result = view.result;
    let didSuppressNotifications = result.suppressNotifications;
    if (!didSuppressNotifications)
      result.suppressNotifications = true
    try {
      findNodes(view.result.root);
    }
    finally {
      if (!didSuppressNotifications)
        result.suppressNotifications = false;
    }

    // For all the nodes we've found, highlight the corresponding
    // index in the tree.
    var resultview = view.view;
    var selection = resultview.selection;
    selection.selectEventsSuppressed = true;
    selection.clearSelection();
    // Open nodes containing found items.
    for (var i = 0; i < nodesToOpen.length; i++) {
      nodesToOpen[i].containerOpen = true;
    }
    for (var i = 0; i < nodes.length; i++) {
      if (PlacesUtils.nodeIsContainer(nodes[i]))
        continue;

      var index = resultview.treeIndexForNode(nodes[i]);
      selection.rangedSelect(index, index, true);
    }
    selection.selectEventsSuppressed = false;
  },

  selectFolderByItemId: function PC_selectFolderByItemId(view, aFolderItemId, aItemId) {
    // Library
    if (view.getAttribute("id") == "placeContent") {
      view = document.getElementById("placesList");
      // Select a folder node in folder pane.
      this.selectItems2(view, [aFolderItemId]);
      view.selectItems([aFolderItemId]);
      if (view.currentIndex)
        view.treeBoxObject.ensureRowIsVisible(view.currentIndex);
      // Reselect child node.
      setTimeout(function(aItemId, view) {
        var aView = view.ownerDocument.getElementById("placeContent");
        aView.selectItems([aItemId]);
        if (aView.currentIndex)
          aView.treeBoxObject.ensureRowIsVisible(aView.currentIndex);
      }, 0, aItemId, view);
      return;
    }

    // Bookmarks Sidebar
    if (!view)
      return;
    view.place = view.place;

    if ('FlatBookmarksOverlay' in window) {
      var sidebarwin = view.ownerDocument.defaultView;
      var searchBox = sidebarwin.document.getElementById("search-box");
      searchBox.value = "";
      searchBox.doCommand();
      sidebarwin.FlatBookmarks._setTreePlace(sidebarwin.FlatBookmarks._makePlaceForFolder(aFolderItemId));
      view.selectItems([aItemId]);
      var tbo = view.treeBoxObject;
      tbo.ensureRowIsVisible(view.currentIndex);
      view.focus();
      return;
    }

    view.findNode = function flatChildNodes(node, aIDs) {
      var ids = aIDs; // Don't manipulate the caller's array.

      // Array of nodes found by findNodes which are to be selected
      var nodes = [];

      // Array of nodes found by findNodes which should be opened
      var nodesToOpen = [];

      // A set of URIs of container-nodes that were previously searched,
      // and thus shouldn't be searched again. This is empty at the initial
      // start of the recursion and gets filled in as the recursion
      // progresses.
      var nodesURIChecked = [];

      /**
       * Recursively search through a node's children for items
       * with the given IDs. When a matching item is found, remove its ID
       * from the IDs array, and add the found node to the nodes dictionary.
       *
       * NOTE: This method will leave open any node that had matching items
       * in its subtree.
       */
      function findNodes(node) {
        var foundOne = false;
        // See if node matches an ID we wanted; add to results.
        // For simple folder queries, check both itemId and the concrete
        // item id.
        var index = ids.indexOf(node.itemId);
        if (index == -1 &&
            node.type == Components.interfaces.nsINavHistoryResultNode.RESULT_TYPE_FOLDER_SHORTCUT) {
          index = ids.indexOf(PlacesUtils.asQuery(node).folderItemId); // xxx Bug 556739 3.7a5pre
        }

        if (index != -1) {
          nodes.push(node);
          foundOne = true;
          ids.splice(index, 1);
        }

        if (ids.length == 0 || !PlacesUtils.nodeIsContainer(node) ||
            nodesURIChecked.indexOf(node.uri) != -1)
          return foundOne;

        nodesURIChecked.push(node.uri);
        PlacesUtils.asContainer(node); // xxx Bug 556739 3.7a6pre
        // Remember the beginning state so that we can re-close
        // this node if we don't find any additional results here.
        var previousOpenness = node.containerOpen;
        node.containerOpen = true;
        for (var child = 0;  child < node.childCount && ids.length > 0;
             child++) {
          var childNode = node.getChild(child);
          if (PlacesUtils.nodeIsQuery(childNode))
            continue;
          var found = findNodes(childNode);
          if (!foundOne)
            foundOne = found;
        }

        // If we didn't find any additional matches in this node's
        // subtree, revert the node to its previous openness.
        if (foundOne)
          nodesToOpen.unshift(node);
        node.containerOpen = previousOpenness;
        return foundOne;
      } // findNodes

      // Disable notifications while looking for nodes.
      let result = this.result;
      let didSuppressNotifications = result.suppressNotifications;
      if (!didSuppressNotifications)
        result.suppressNotifications = true
      try {
        findNodes(this.result.root);
      }
      finally {
        if (!didSuppressNotifications)
          result.suppressNotifications = false;
      }

      // Open nodes containing found items.
      for (var i = 0; i < nodesToOpen.length; i++) {
        nodesToOpen[i].containerOpen = true;
      }
      return nodes;
    }; // findNode

    // For all the nodes we've found, highlight the corresponding
    // index in the tree.
    var resultview = view.view;
    var selection = view.view.selection;
    selection.selectEventsSuppressed = true;
    selection.clearSelection();
    var nodes = view.findNode(view.result.root, [aFolderItemId]);
    if (nodes.length > 0) {
      var index = resultview.treeIndexForNode(nodes[0]);
      nodes = view.findNode(nodes[0], [aItemId]);
      if (nodes.length > 0) {
        index = resultview.treeIndexForNode(nodes[0]);
        selection.rangedSelect(index, index, true);
      }
    }
    selection.selectEventsSuppressed = false;

    var tbo = view.treeBoxObject;
    tbo.ensureRowIsVisible(view.currentIndex);
    view.focus();
    return;
  },

  /**
   * Walk the list of folders we're removing in this delete operation, and
   * see if the selected node specified is already implicitly being removed
   * because it is a child of that folder.
   * @param   node
   *          Node to check for containment.
   * @param   pastFolders
   *          List of folders the calling function has already traversed
   * @returns true if the node should be skipped, false otherwise.
   */
  _shouldSkipNode: function PC_shouldSkipNode(node, pastFolders) {
    /**
     * Determines if a node is contained by another node within a resultset.
     * @param   node
     *          The node to check for containment for
     * @param   parent
     *          The parent container to check for containment in
     * @returns true if node is a member of parent's children, false otherwise.
     */
    function isContainedBy(node, parent) {
      var cursor = node.parent;
      while (cursor) {
        if (cursor == parent)
          return true;
        cursor = cursor.parent;
      }
      return false;
    }

      for (var j = 0; j < pastFolders.length; ++j) {
        if (isContainedBy(node, pastFolders[j]))
          return true;
      }
      return false;
  },

  /**
   * Creates a set of transactions for the removal of a range of items.
   * A range is an array of adjacent nodes in a view.
   * @param   [in] range
   *          An array of nodes to remove. Should all be adjacent.
   * @param   [out] transactions
   *          An array of transactions.
   * @param   [optional] removedFolders
   *          An array of folder nodes that have already been removed.
   */
  _removeRange: function PC__removeRange(range, transactions, removedFolders) {
    NS_ASSERT(transactions instanceof Array, "Must pass a transactions array");
    if (!removedFolders)
      removedFolders = [];

    for (var i = 0; i < range.length; ++i) {
      var node = range[i];
      if (this._shouldSkipNode(node, removedFolders))
        continue;

      if (PlacesUtils.nodeIsTagQuery(node.parent)) {
        // This is a uri node inside a tag container.  It needs a special
        // untag transaction.
        var tagItemId = PlacesUtils.getConcreteItemId(node.parent);
        var uri = NetUtil.newURI(node.uri);
        let txn = new PlacesUntagURITransaction(uri, [tagItemId]);
        transactions.push(txn);
      }
      else if (PlacesUtils.nodeIsTagQuery(node) && node.parent &&
               PlacesUtils.nodeIsQuery(node.parent) &&
               PlacesUtils.asQuery(node.parent).queryOptions.resultType ==
                 Ci.nsINavHistoryQueryOptions.RESULTS_AS_TAG_QUERY) {
        // This is a tag container.
        // Untag all URIs tagged with this tag only if the tag container is
        // child of the "Tags" query in the library, in all other places we
        // must only remove the query node.
        var tag = node.title;
        var URIs = PlacesUtils.tagging.getURIsForTag(tag);
        for (var j = 0; j < URIs.length; j++) {
          let txn = new PlacesUntagURITransaction(URIs[j], [tag]);
          transactions.push(txn);
        }
      }
      else if (PlacesUtils.nodeIsURI(node) &&
               PlacesUtils.nodeIsQuery(node.parent) &&
               PlacesUtils.asQuery(node.parent).queryOptions.queryType ==
                 Ci.nsINavHistoryQueryOptions.QUERY_TYPE_HISTORY) {
        // This is a uri node inside an history query.
        PlacesUtils.bhistory.removePage(NetUtil.newURI(node.uri));
        // History deletes are not undoable, so we don't have a transaction.
      }
      else if (node.itemId == -1 &&
               PlacesUtils.nodeIsQuery(node) &&
               PlacesUtils.asQuery(node).queryOptions.queryType ==
                 Ci.nsINavHistoryQueryOptions.QUERY_TYPE_HISTORY) {
        // This is a dynamically generated history query, like queries
        // grouped by site, time or both.  Dynamically generated queries don't
        // have an itemId even if they are descendants of a bookmark.
        this._removeHistoryContainer(node);
        // History deletes are not undoable, so we don't have a transaction.
      }
      else {
        // This is a common bookmark item.
        if (PlacesUtils.nodeIsFolder(node)) {
          // If this is a folder we add it to our array of folders, used
          // to skip nodes that are children of an already removed folder.
          removedFolders.push(node);
        }
        let txn = new PlacesRemoveItemTransaction(node.itemId);
        transactions.push(txn);
      }
    }
  },

  /**
   * Removes the set of selected ranges from bookmarks.
   * @param   txnName
   *          See |remove|.
   */
  _removeRowsFromBookmarks: function PC__removeRowsFromBookmarks(txnName) {
    var ranges = this._view.removableSelectionRanges;
    var transactions = [];
    var removedFolders = [];

    for (var i = 0; i < ranges.length; i++)
      this._removeRange(ranges[i], transactions, removedFolders);

    if (transactions.length > 0) {
      var txn = new PlacesAggregatedTransaction(txnName, transactions);
      PlacesUtils.transactionManager.doTransaction(txn);
    }
  },

  /**
   * Removes the set of selected ranges from history.
   *
   * @note history deletes are not undoable.
   */
  _removeRowsFromHistory: function PC__removeRowsFromHistory() {
    let nodes = this._view.selectedNodes;
    let URIs = [];
    for (let i = 0; i < nodes.length; ++i) {
      let node = nodes[i];
      if (PlacesUtils.nodeIsURI(node)) {
        let uri = NetUtil.newURI(node.uri);
        // Avoid duplicates.
        if (URIs.indexOf(uri) < 0) {
          URIs.push(uri);
        }
      }
      else if (PlacesUtils.nodeIsQuery(node) &&
               PlacesUtils.asQuery(node).queryOptions.queryType ==
                 Ci.nsINavHistoryQueryOptions.QUERY_TYPE_HISTORY) {
        this._removeHistoryContainer(node);
      }
    }

    // Do removal in chunks to give some breath to main-thread.
    function pagesChunkGenerator(aURIs) {
      while (aURIs.length) {
        let URIslice = aURIs.splice(0, REMOVE_PAGES_CHUNKLEN);
        PlacesUtils.bhistory.removePages(URIslice, URIslice.length);
        Services.tm.mainThread.dispatch(function() {
          try {
            gen.next();
          } catch (ex if ex instanceof StopIteration) {}
        }, Ci.nsIThread.DISPATCH_NORMAL);
        yield undefined;
      }
    }
    let gen = pagesChunkGenerator(URIs);
    gen.next();
  },

  /**
   * Removes history visits for an history container node.
   * @param   [in] aContainerNode
   *          The container node to remove.
   *
   * @note history deletes are not undoable.
   */
  _removeHistoryContainer: function PC__removeHistoryContainer(aContainerNode) {
    if (PlacesUtils.nodeIsHost(aContainerNode)) {
      // Site container.
      PlacesUtils.bhistory.removePagesFromHost(aContainerNode.title, true);
    }
    else if (PlacesUtils.nodeIsDay(aContainerNode)) {
      // Day container.
      let query = aContainerNode.getQueries()[0];
      let beginTime = query.beginTime;
      let endTime = query.endTime;
      NS_ASSERT(query && beginTime && endTime,
                "A valid date container query should exist!");
      // We want to exclude beginTime from the removal because
      // removePagesByTimeframe includes both extremes, while date containers
      // exclude the lower extreme.  So, if we would not exclude it, we would
      // end up removing more history than requested.
      PlacesUtils.bhistory.removePagesByTimeframe(beginTime + 1, endTime);
    }
  },

  /**
   * Removes the selection
   * @param   aTxnName
   *          A name for the transaction if this is being performed
   *          as part of another operation.
   */
  remove: function PC_remove(aTxnName) {
    if (!this._hasRemovableSelection(false))
      return;

    NS_ASSERT(aTxnName !== undefined, "Must supply Transaction Name");

    var root = this._view.result.root;

    if (PlacesUtils.nodeIsFolder(root))
      this._removeRowsFromBookmarks(aTxnName);
    else if (PlacesUtils.nodeIsQuery(root)) {
      var queryType = PlacesUtils.asQuery(root).queryOptions.queryType;
      if (queryType == Ci.nsINavHistoryQueryOptions.QUERY_TYPE_BOOKMARKS)
        this._removeRowsFromBookmarks(aTxnName);
      else if (queryType == Ci.nsINavHistoryQueryOptions.QUERY_TYPE_HISTORY)
        this._removeRowsFromHistory();
      else
        NS_ASSERT(false, "implement support for QUERY_TYPE_UNIFIED");
    }
    else
      NS_ASSERT(false, "unexpected root");
  },

  /**
   * Fills a DataTransfer object with the content of the selection that can be
   * dropped elsewhere.
   * @param   aEvent
   *          The dragstart event.
   */
  setDataTransfer: function PC_setDataTransfer(aEvent) {
    let dt = aEvent.dataTransfer;
    let doCopy = ["copyLink", "copy", "link"].indexOf(dt.effectAllowed) != -1;

    let result = this._view.result;
    let didSuppressNotifications = result.suppressNotifications;
    if (!didSuppressNotifications)
      result.suppressNotifications = true;

    function addData(type, index, overrideURI) {
      let wrapNode = PlacesUtils.wrapNode(node, type, overrideURI, doCopy);
      dt.mozSetDataAt(type, wrapNode, index);
    }

    function addURIData(index, overrideURI) {
      addData(PlacesUtils.TYPE_X_MOZ_URL, index, overrideURI);
      addData(PlacesUtils.TYPE_UNICODE, index, overrideURI);
      addData(PlacesUtils.TYPE_HTML, index, overrideURI);
    }

    try {
      let nodes = this._view.draggableSelection;
      for (let i = 0; i < nodes.length; ++i) {
        var node = nodes[i];

        // This order is _important_! It controls how this and other
        // applications select data to be inserted based on type.
        addData(PlacesUtils.TYPE_X_MOZ_PLACE, i);

        // Drop the feed uri for livemark containers
        let livemarkInfo = this.getCachedLivemarkInfo(node);
        if (livemarkInfo) {
          addURIData(i, livemarkInfo.feedURI.spec);
        }
        else if (node.uri) {
          addURIData(i);
        }
      }
    }
    finally {
      if (!didSuppressNotifications)
        result.suppressNotifications = false;
    }
  },

  get clipboardAction () {
    let action = {};
    let actionOwner;
    try {
      let xferable = Cc["@mozilla.org/widget/transferable;1"].
                     createInstance(Ci.nsITransferable);
      xferable.init(null);
      xferable.addDataFlavor(PlacesUtils.TYPE_X_MOZ_PLACE_ACTION)
      this.clipboard.getData(xferable, Ci.nsIClipboard.kGlobalClipboard);
      xferable.getTransferData(PlacesUtils.TYPE_X_MOZ_PLACE_ACTION, action, {});
      [action, actionOwner] =
        action.value.QueryInterface(Ci.nsISupportsString).data.split(",");
    } catch(ex) {
      // Paste from external sources don't have any associated action, just
      // fallback to a copy action.
      return "copy";
    }
    // For cuts also check who inited the action, since cuts across different
    // instances should instead be handled as copies (The sources are not
    // available for this instance).
    if (action == "cut" && actionOwner != this.profileName)
      action = "copy";

    return action;
  },

  _releaseClipboardOwnership: function PC__releaseClipboardOwnership() {
    if (this.cutNodes.length > 0) {
      // This clears the logical clipboard, doesn't remove data.
      this.clipboard.emptyClipboard(Ci.nsIClipboard.kGlobalClipboard);
    }
  },

  _clearClipboard: function PC__clearClipboard() {
    let xferable = Cc["@mozilla.org/widget/transferable;1"].
                   createInstance(Ci.nsITransferable);
    xferable.init(null);
    // Empty transferables may cause crashes, so just add an unknown type.
    const TYPE = "text/x-moz-place-empty";
    xferable.addDataFlavor(TYPE);
    xferable.setTransferData(TYPE, PlacesUtils.toISupportsString(""), 0);
    this.clipboard.setData(xferable, null, Ci.nsIClipboard.kGlobalClipboard);
  },

  _populateClipboard: function PC__populateClipboard(aNodes, aAction) {
    // This order is _important_! It controls how this and other applications
    // select data to be inserted based on type.
    let contents = [
      { type: PlacesUtils.TYPE_X_MOZ_PLACE, entries: [] },
      { type: PlacesUtils.TYPE_X_MOZ_URL, entries: [] },
      { type: PlacesUtils.TYPE_HTML, entries: [] },
      { type: PlacesUtils.TYPE_UNICODE, entries: [] },
    ];

    // Avoid handling descendants of a copied node, the transactions take care
    // of them automatically.
    let copiedFolders = [];
    aNodes.forEach(function (node) {
      if (this._shouldSkipNode(node, copiedFolders))
        return;
      if (PlacesUtils.nodeIsFolder(node))
        copiedFolders.push(node);

      let livemarkInfo = this.getCachedLivemarkInfo(node);
      let overrideURI = livemarkInfo ? livemarkInfo.feedURI.spec : null;
      let resolveShortcuts = !PlacesControllerDragHelper.canMoveNode(node);

      contents.forEach(function (content) {
        content.entries.push(
          PlacesUtils.wrapNode(node, content.type, overrideURI, resolveShortcuts)
        );
      });
    }, this);

    function addData(type, data) {
      xferable.addDataFlavor(type);
      xferable.setTransferData(type, PlacesUtils.toISupportsString(data),
                               data.length * 2);
    }

    let xferable = Cc["@mozilla.org/widget/transferable;1"].
                   createInstance(Ci.nsITransferable);
    xferable.init(null);
    let hasData = false;
    // This order matters here!  It controls how this and other applications
    // select data to be inserted based on type.
    contents.forEach(function (content) {
      if (content.entries.length > 0) {
        hasData = true;
        let glue =
          content.type == PlacesUtils.TYPE_X_MOZ_PLACE ? "," : PlacesUtils.endl;
        addData(content.type, content.entries.join(glue));
      }
    });

    // Track the exected action in the xferable.  This must be the last flavor
    // since it's the least preferred one.
    // Enqueue a unique instance identifier to distinguish operations across
    // concurrent instances of the application.
    addData(PlacesUtils.TYPE_X_MOZ_PLACE_ACTION, aAction + "," + this.profileName);

    if (hasData) {
      this.clipboard.setData(xferable,
                             this.cutNodes.length > 0 ? this : null,
                             Ci.nsIClipboard.kGlobalClipboard);
    }
  },

  _cutNodes: [],
  get cutNodes() this._cutNodes,
  set cutNodes(aNodes) {
    let self = this;
    function updateCutNodes(aValue) {
      self._cutNodes.forEach(function (aNode) {
        self._view.toggleCutNode(aNode, aValue);
      });
    }

    updateCutNodes(false);
    this._cutNodes = aNodes;
    updateCutNodes(true);
    return aNodes;
  },

  /**
   * Copy Bookmarks and Folders to the clipboard
   */
  copy: function PC_copy() {
    let result = this._view.result;
    let didSuppressNotifications = result.suppressNotifications;
    if (!didSuppressNotifications)
      result.suppressNotifications = true;
    try {
      this._populateClipboard(this._view.selectedNodes, "copy");
    }
    finally {
      if (!didSuppressNotifications)
        result.suppressNotifications = false;
    }
  },

  /**
   * Cut Bookmarks and Folders to the clipboard
   */
  cut: function PC_cut() {
    let result = this._view.result;
    let didSuppressNotifications = result.suppressNotifications;
    if (!didSuppressNotifications)
      result.suppressNotifications = true;
    try {
      this._populateClipboard(this._view.selectedNodes, "cut");
      this.cutNodes = this._view.selectedNodes;
    }
    finally {
      if (!didSuppressNotifications)
        result.suppressNotifications = false;
    }
  },

  /**
   * Paste Bookmarks and Folders from the clipboard
   */
  paste: function PC_paste() {
    // No reason to proceed if there isn't a valid insertion point.
    let ip = this._view.insertionPoint;
    if (!ip)
      throw Cr.NS_ERROR_NOT_AVAILABLE;

    let action = this.clipboardAction;

    let xferable = Cc["@mozilla.org/widget/transferable;1"].
                   createInstance(Ci.nsITransferable);
    xferable.init(null);
    // This order matters here!  It controls the preferred flavors for this
    // paste operation.
    [ PlacesUtils.TYPE_X_MOZ_PLACE,
      PlacesUtils.TYPE_X_MOZ_URL,
      PlacesUtils.TYPE_UNICODE,
    ].forEach(function (type) xferable.addDataFlavor(type));

    this.clipboard.getData(xferable, Ci.nsIClipboard.kGlobalClipboard);

    // Now get the clipboard contents, in the best available flavor.
    let data = {}, type = {}, items = [];
    try {
      xferable.getAnyTransferData(type, data, {});
      data = data.value.QueryInterface(Ci.nsISupportsString).data;
      type = type.value;
      items = PlacesUtils.unwrapNodes(data, type);
    } catch(ex) {
      // No supported data exists or nodes unwrap failed, just bail out.
      return;
    }

    let transactions = [];
    let insertionIndex = ip.index;
    for (let i = 0; i < items.length; ++i) {
      if (ip.isTag) {
        // Pasting into a tag container means tagging the item, regardless of
        // the requested action.
        let tagTxn = new PlacesTagURITransaction(NetUtil.newURI(items[i].uri),
                                                 [ip.itemId]);
        transactions.push(tagTxn);
        continue;
      }

      // Adjust index to make sure items are pasted in the correct position.
      // If index is DEFAULT_INDEX, items are just appended.
      if (ip.index != PlacesUtils.bookmarks.DEFAULT_INDEX)
        insertionIndex = ip.index + i;

      transactions.push(
        PlacesUIUtils.makeTransaction(items[i], type, ip.itemId,
                                      insertionIndex, action == "copy")
      );
    }

    let aggregatedTxn = new PlacesAggregatedTransaction("Paste", transactions);
    PlacesUtils.transactionManager.doTransaction(aggregatedTxn);

    // Cut/past operations are not repeatable, so clear the clipboard.
    if (action == "cut") {
      this._clearClipboard();
    }

    // Select the pasted items, they should be consecutive.
    let insertedNodeIds = [];
    for (let i = 0; i < transactions.length; ++i) {
      insertedNodeIds.push(
        PlacesUtils.bookmarks.getIdForItemAt(ip.itemId, ip.index + i)
      );
    }
    if (insertedNodeIds.length > 0)
      this._view.selectItems(insertedNodeIds, false);
  },

  /**
   * Cache the livemark info for a node.  This allows the controller and the
   * views to treat the given node as a livemark.
   * @param aNode
   *        a places result node.
   * @param aLivemarkInfo
   *        a mozILivemarkInfo object.
   */
  cacheLivemarkInfo: function PC_cacheLivemarkInfo(aNode, aLivemarkInfo) {
    this._cachedLivemarkInfoObjects.set(aNode, aLivemarkInfo);
  },

  /**
   * Returns whether or not there's cached mozILivemarkInfo object for a node.
   * @param aNode
   *        a places result node.
   * @return true if there's a cached mozILivemarkInfo object for
   * aNode, false otherwise.
   */
  hasCachedLivemarkInfo: function PC_hasCachedLivemarkInfo(aNode)
    this._cachedLivemarkInfoObjects.has(aNode),

  /**
   * Returns the cached livemark info for a node, if set by cacheLivemarkInfo,
   * null otherwise.
   * @param aNode
   *        a places result node.
   * @return the mozILivemarkInfo object for aNode, if set, null otherwise.
   */
  getCachedLivemarkInfo: function PC_getCachedLivemarkInfo(aNode)
    this._cachedLivemarkInfoObjects.get(aNode, null)
};

/**
 * Handles drag and drop operations for views. Note that this is view agnostic!
 * You should not use PlacesController._view within these methods, since
 * the view that the item(s) have been dropped on was not necessarily active.
 * Drop functions are passed the view that is being dropped on.
 */
let PlacesControllerDragHelper = {
  /**
   * DOM Element currently being dragged over
   */
  currentDropTarget: null,

  /**
   * Determines if the mouse is currently being dragged over a child node of
   * this menu. This is necessary so that the menu doesn't close while the
   * mouse is dragging over one of its submenus
   * @param   node
   *          The container node
   * @returns true if the user is dragging over a node within the hierarchy of
   *          the container, false otherwise.
   */
  draggingOverChildNode: function PCDH_draggingOverChildNode(node) {
    let currentNode = this.currentDropTarget;
    while (currentNode) {
      if (currentNode == node)
        return true;
      currentNode = currentNode.parentNode;
    }
    return false;
  },

  /**
   * @returns The current active drag session. Returns null if there is none.
   */
  getSession: function PCDH__getSession() {
    return this.dragService.getCurrentSession();
  },

  /**
   * Extract the first accepted flavor from a list of flavors.
   * @param aFlavors
   *        The flavors list of type nsIDOMDOMStringList.
   */
  getFirstValidFlavor: function PCDH_getFirstValidFlavor(aFlavors) {
    for (let i = 0; i < aFlavors.length; i++) {
      if (this.GENERIC_VIEW_DROP_TYPES.indexOf(aFlavors[i]) != -1)
        return aFlavors[i];
    }

    // If no supported flavor is found, check if data includes text/plain
    // contents.  If so, request them as text/unicode, a conversion will happen
    // automatically.
    if (aFlavors.contains("text/plain")) {
        return PlacesUtils.TYPE_UNICODE;
    }

    return null;
  },

  /**
   * Determines whether or not the data currently being dragged can be dropped
   * on a places view.
   * @param ip
   *        The insertion point where the items should be dropped.
   */
  canDrop: function PCDH_canDrop(ip, dt) {
    let dropCount = dt.mozItemCount;

    // Check every dragged item.
    for (let i = 0; i < dropCount; i++) {
      let flavor = this.getFirstValidFlavor(dt.mozTypesAt(i));
      if (!flavor)
        return false;

      // Urls can be dropped on any insertionpoint.
      // XXXmano: remember that this method is called for each dragover event!
      // Thus we shouldn't use unwrapNodes here at all if possible.
      // I think it would be OK to accept bogus data here (e.g. text which was
      // somehow wrapped as TAB_DROP_TYPE, this is not in our control, and
      // will just case the actual drop to be a no-op), and only rule out valid
      // expected cases, which are either unsupported flavors, or items which
      // cannot be dropped in the current insertionpoint. The last case will
      // likely force us to use unwrapNodes for the private data types of
      // places.
      if (flavor == TAB_DROP_TYPE)
        continue;

      let data = dt.mozGetDataAt(flavor, i);
      let dragged;
      try {
        dragged = PlacesUtils.unwrapNodes(data, flavor)[0];
      }
      catch (e) {
        return false;
      }

      // Only bookmarks and urls can be dropped into tag containers.
      if (ip.isTag && ip.orientation == Ci.nsITreeView.DROP_ON &&
          dragged.type != PlacesUtils.TYPE_X_MOZ_URL &&
          (dragged.type != PlacesUtils.TYPE_X_MOZ_PLACE ||
           (dragged.uri && dragged.uri.startsWith("place:")) ))
        return false;

      // The following loop disallows the dropping of a folder on itself or
      // on any of its descendants.
      if (dragged.type == PlacesUtils.TYPE_X_MOZ_PLACE_CONTAINER ||
          (dragged.uri && dragged.uri.startsWith("place:")) ) {
        let parentId = ip.itemId;
        while (parentId != PlacesUtils.placesRootId) {
          if (dragged.concreteId == parentId || dragged.id == parentId)
            return false;
          parentId = PlacesUtils.bookmarks.getFolderIdForItem(parentId);
        }
      }
    }
    return true;
  },


  /**
   * Determines if a node can be moved.
   *
   * @param   aNode
   *          A nsINavHistoryResultNode node.
   * @returns True if the node can be moved, false otherwise.
   */
  canMoveNode:
  function PCDH_canMoveNode(aNode) {
    // Can't move query root.
    if (!aNode.parent)
      return false;

    let parentId = PlacesUtils.getConcreteItemId(aNode.parent);
    let concreteId = PlacesUtils.getConcreteItemId(aNode);

    // Can't move children of tag containers.
    if (PlacesUtils.nodeIsTagQuery(aNode.parent))
      return false;

    // Can't move children of read-only containers.
    if (PlacesUtils.nodeIsReadOnly(aNode.parent))
      return false;

    // Check for special folders, etc.
    if (PlacesUtils.nodeIsContainer(aNode) &&
        !this.canMoveContainer(aNode.itemId, parentId))
      return false;

    return true;
  },

  /**
   * Determines if a container node can be moved.
   *
   * @param   aId
   *          A bookmark folder id.
   * @param   [optional] aParentId
   *          The parent id of the folder.
   * @returns True if the container can be moved to the target.
   */
  canMoveContainer:
  function PCDH_canMoveContainer(aId, aParentId) {
    if (aId == -1)
      return false;

    // Disallow moving of roots and special folders.
    const ROOTS = [PlacesUtils.placesRootId, PlacesUtils.bookmarksMenuFolderId,
                   PlacesUtils.tagsFolderId, PlacesUtils.unfiledBookmarksFolderId,
                   PlacesUtils.toolbarFolderId];
    if (ROOTS.indexOf(aId) != -1)
      return false;

    // Get parent id if necessary.
    if (aParentId == null || aParentId == -1)
      aParentId = PlacesUtils.bookmarks.getFolderIdForItem(aId);

    if (PlacesUtils.bookmarks.getFolderReadonly(aParentId))
      return false;

    return true;
  },

  /**
   * Handles the drop of one or more items onto a view.
   * @param   insertionPoint
   *          The insertion point where the items should be dropped
   */
  onDrop: function PCDH_onDrop(insertionPoint, dt) {
    let doCopy = ["copy", "link"].indexOf(dt.dropEffect) != -1;

    let transactions = [];
    let dropCount = dt.mozItemCount;
    let movedCount = 0;
    for (let i = 0; i < dropCount; ++i) {
      let flavor = this.getFirstValidFlavor(dt.mozTypesAt(i));
      if (!flavor)
        return;

      let data = dt.mozGetDataAt(flavor, i);
      let unwrapped;
      if (flavor != TAB_DROP_TYPE) {
        // There's only ever one in the D&D case.
        unwrapped = PlacesUtils.unwrapNodes(data, flavor)[0];
      }
      else if (data instanceof XULElement && data.localName == "tab" &&
               data.ownerDocument.defaultView instanceof ChromeWindow) {
        let uri = data.linkedBrowser.currentURI;
        let spec = uri ? uri.spec : "about:blank";
        let title = data.label;
        unwrapped = { uri: spec,
                      title: data.label,
                      type: PlacesUtils.TYPE_X_MOZ_URL};
      }
      else
        throw("bogus data was passed as a tab");

      let index = insertionPoint.index;

      // Adjust insertion index to prevent reversal of dragged items. When you
      // drag multiple elts upward: need to increment index or each successive
      // elt will be inserted at the same index, each above the previous.
      let dragginUp = insertionPoint.itemId == unwrapped.parent &&
                      index < PlacesUtils.bookmarks.getItemIndex(unwrapped.id);
      if (index != -1 && dragginUp)
        index += movedCount++;

      // If dragging over a tag container we should tag the item.
      if (insertionPoint.isTag &&
          insertionPoint.orientation == Ci.nsITreeView.DROP_ON) {
        let uri = NetUtil.newURI(unwrapped.uri);
        let tagItemId = insertionPoint.itemId;
        let tagTxn = new PlacesTagURITransaction(uri, [tagItemId]);
        transactions.push(tagTxn);
      }
      else {
        transactions.push(PlacesUIUtils.makeTransaction(unwrapped,
                          flavor, insertionPoint.itemId,
                          index, doCopy));
      }
    }

    let txn = new PlacesAggregatedTransaction("DropItems", transactions);
    PlacesUtils.transactionManager.doTransaction(txn);
  },

  /**
   * Checks if we can insert into a container.
   * @param   aContainer
   *          The container were we are want to drop
   */
  disallowInsertion: function(aContainer) {
    NS_ASSERT(aContainer, "empty container");
    // Allow dropping into Tag containers.
    if (PlacesUtils.nodeIsTagQuery(aContainer))
      return false;
    // Disallow insertion of items under readonly folders.
    return (!PlacesUtils.nodeIsFolder(aContainer) ||
             PlacesUtils.nodeIsReadOnly(aContainer));
  },

  placesFlavors: [PlacesUtils.TYPE_X_MOZ_PLACE_CONTAINER,
                  PlacesUtils.TYPE_X_MOZ_PLACE_SEPARATOR,
                  PlacesUtils.TYPE_X_MOZ_PLACE],

  // The order matters.
  GENERIC_VIEW_DROP_TYPES: [PlacesUtils.TYPE_X_MOZ_PLACE_CONTAINER,
                            PlacesUtils.TYPE_X_MOZ_PLACE_SEPARATOR,
                            PlacesUtils.TYPE_X_MOZ_PLACE,
                            PlacesUtils.TYPE_X_MOZ_URL,
                            TAB_DROP_TYPE,
                            PlacesUtils.TYPE_UNICODE],
};


XPCOMUtils.defineLazyServiceGetter(PlacesControllerDragHelper, "dragService",
                                   "@mozilla.org/widget/dragservice;1",
                                   "nsIDragService");

function goUpdatePlacesCommands() {
  // Get the controller for one of the places commands.
  var placesController = doGetPlacesControllerForCommand("placesCmd_open");
  function updatePlacesCommand(aCommand) {
    goSetCommandEnabled(aCommand, placesController &&
                                  placesController.isCommandEnabled(aCommand));
  }

  updatePlacesCommand("placesCmd_open");
  updatePlacesCommand("placesCmd_open:window");
  updatePlacesCommand("placesCmd_open:tab");
  updatePlacesCommand("placesCmd_new:folder");
  updatePlacesCommand("placesCmd_new:bookmark");
  updatePlacesCommand("placesCmd_new:livemark");
  updatePlacesCommand("placesCmd_new:separator");
  updatePlacesCommand("placesCmd_show:info");
  updatePlacesCommand("placesCmd_moveBookmarks");
  updatePlacesCommand("placesCmd_reload");
  updatePlacesCommand("placesCmd_sortBy:name");
  updatePlacesCommand("placesCmd_openParentFolder");
  updatePlacesCommand("placesCmd_cut");
  updatePlacesCommand("placesCmd_copy");
  updatePlacesCommand("placesCmd_paste");
  updatePlacesCommand("placesCmd_delete");
}

function doGetPlacesControllerForCommand(aCommand)
{
  // A context menu may be built for non-focusable views.  Thus, we first try
  // to look for a view associated with document.popupNode
  let popupNode;
  try {
    popupNode = document.popupNode;
  } catch (e) {
    // The document went away (bug 797307).
    return null;
  }
  if (popupNode) {
    let view = PlacesUIUtils.getViewForNode(popupNode);
    if (view && view._contextMenuShown)
      return view.controllers.getControllerForCommand(aCommand);
  }

  // When we're not building a context menu, only focusable views
  // are possible.  Thus, we can safely use the command dispatcher.
  let controller = top.document.commandDispatcher
                      .getControllerForCommand(aCommand);
  if (controller)
    return controller;

  return null;
}

function goDoPlacesCommand(aCommand)
{
  let controller = doGetPlacesControllerForCommand(aCommand);
  if (controller && controller.isCommandEnabled(aCommand))
    controller.doCommand(aCommand);
}

