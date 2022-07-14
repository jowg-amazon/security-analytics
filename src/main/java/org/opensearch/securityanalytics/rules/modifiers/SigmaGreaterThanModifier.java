/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.modifiers;

import org.opensearch.securityanalytics.rules.objects.SigmaDetectionItem;
import org.opensearch.securityanalytics.rules.types.SigmaCompareExpression;

import java.util.List;

public class SigmaGreaterThanModifier extends SigmaCompareModifier {

    public SigmaGreaterThanModifier(SigmaDetectionItem detectionItem, List<Class<? extends SigmaModifier>> appliedModifiers) {
        super(detectionItem, appliedModifiers);
        this.setOp(SigmaCompareExpression.CompareOperators.GT);
    }
}