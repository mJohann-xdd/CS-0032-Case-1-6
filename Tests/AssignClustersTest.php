<?php
use PHPUnit\Framework\TestCase;
require_once __DIR__ . '/../run_clustering.php';

class AssignClustersTest extends TestCase {

    public function testClusterAssignment() {
        $data = [[1,1],[5,5],[9,9]];
        $centroids = [[0,0],[10,10]];
        $clusters = assignClusters($data, $centroids);
        $this->assertEquals([0,1,1], $clusters);
    }

    public function testEmptyData() {
        $data = [];
        $centroids = [[0,0],[1,1]];
        $clusters = assignClusters($data, $centroids);
        $this->assertEmpty($clusters);
    }
}
