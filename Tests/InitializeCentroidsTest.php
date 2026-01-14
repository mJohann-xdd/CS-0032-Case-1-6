<?php
use PHPUnit\Framework\TestCase;
require_once __DIR__ . '/../run_clustering.php';

class InitializeCentroidsTest extends TestCase {

    public function testKMeansPlusPlusRandomness() {
        $data = [
            [1,2], [3,4], [5,6], [7,8], [9,10]
        ];
        $centroids1 = initializeCentroids($data, 2);
        $centroids2 = initializeCentroids($data, 2);
        // Check centroids are arrays
        $this->assertCount(2, $centroids1);
        $this->assertCount(2, $centroids2);
        // Run multiple times to see they are not always identical
        $this->assertNotEquals($centroids1, $centroids2);
    }

    public function testNumberOfCentroids() {
        $data = [[1,1],[2,2],[3,3]];
        $centroids = initializeCentroids($data, 2);
        $this->assertCount(2, $centroids);
    }
}
