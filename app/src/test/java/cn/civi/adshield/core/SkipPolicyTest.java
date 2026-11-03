package cn.civi.adshield.core;

import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class SkipPolicyTest {
    @Test
    public void matchesOnlyConservativeSkipAdLabels() {
        assertTrue(SkipPolicy.matchesLabel("跳过"));
        assertTrue(SkipPolicy.matchesLabel("跳过广告"));
        assertTrue(SkipPolicy.matchesLabel(" 跳过 5 "));
        assertTrue(SkipPolicy.matchesLabel("5s 跳过"));
        assertTrue(SkipPolicy.matchesLabel("跳过广告 5 秒"));
        assertTrue(SkipPolicy.matchesLabel("Skip ad"));
        assertTrue(SkipPolicy.matchesLabel("Skip ad 5 seconds"));

        assertFalse(SkipPolicy.matchesLabel(null));
        assertFalse(SkipPolicy.matchesLabel(""));
        assertFalse(SkipPolicy.matchesLabel("跳过登录"));
        assertFalse(SkipPolicy.matchesLabel("跳过设置"));
        assertFalse(SkipPolicy.matchesLabel("Skip"));
        assertFalse(SkipPolicy.matchesLabel("Skip intro"));
    }

    @Test
    public void allowsOnlySmallNodesEntirelyInUpperRightRegion() {
        assertTrue(SkipPolicy.allowedBounds(600, 10, 900, 100, 1000, 1000));

        assertFalse(SkipPolicy.allowedBounds(499, 10, 800, 100, 1000, 1000));
        assertFalse(SkipPolicy.allowedBounds(600, -1, 800, 100, 1000, 1000));
        assertFalse(SkipPolicy.allowedBounds(600, 10, 1001, 100, 1000, 1000));
        assertFalse(SkipPolicy.allowedBounds(600, 10, 800, 301, 1000, 1000));
        assertFalse(SkipPolicy.allowedBounds(500, 10, 951, 100, 1000, 1000));
        assertFalse(SkipPolicy.allowedBounds(600, 10, 800, 161, 1000, 1000));
        assertFalse(SkipPolicy.allowedBounds(600, 10, 600, 100, 1000, 1000));
        assertFalse(SkipPolicy.allowedBounds(0, 0, 20, 20, 0, 1000));
        assertFalse(SkipPolicy.allowedBounds(Integer.MAX_VALUE, 10, Integer.MIN_VALUE,
                100, 1000, 1000));
    }
}
