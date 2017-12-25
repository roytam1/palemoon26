/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.goanna.sync.repositories;

import org.mozilla.goanna.sync.SyncException;

public class BookmarkNeedsReparentingException extends SyncException {

  private static final long serialVersionUID = -7018336108709392800L;

  public BookmarkNeedsReparentingException(Exception ex) {
    super(ex);
  }

}