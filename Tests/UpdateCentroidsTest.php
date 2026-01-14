<?php
use PHPUnit\Framework\TestCase;
require_once __DIR__ . '/../run_clustering.php';

class UpdateCentroidsTest extends TestCase {

    public function testCentroidUpdate() {
        $clusters = [
            0 => [[1,1],[2,2]],
            1 => [[5,5],[7,7]]
        ];
        $updated = updateCentroids($clusters);
        $this->assertEquals([1.5,1.5], $updated[0]);
        $this->assertEquals([6,6], $updated[1]);
    }

    public function testEmptyClusters() {
        $clusters = [];
        $updated = updateCentroids($clusters);
        $this->assertEmpty($updated);
    }
}
